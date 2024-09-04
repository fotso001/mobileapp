import express from 'express';
import http from 'http'; // New import
import { Server as SocketServer } from 'socket.io'; // New import
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import morgan from 'morgan';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise.js';
import { console } from 'inspector';

dotenv.config();


const app = express();
const server = http.createServer(app); // Create an HTTP server
const io = new SocketServer(server, { cors: { origin: '*' } }); // Attach Socket.IO to the server


const JWT_SECRET = process.env.JWT_SECRET || 'default_jwt_secret';

app.use(cors({
    origin: ['http://localhost:3000'],
    methods: ["POST", "GET", "PUT", "DELETE"],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());
app.use(morgan('dev'));
app.use(cookieParser());
// app.use(bodyParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set true in production with HTTPS
        maxAge: 1000 * 60 * 60 * 24
    }
}));

const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || "", // Replace with your actual password
    database: process.env.DB_NAME || 'gesparking',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});



// Middleware pour vérifier le token JWT et les rôles
const authMiddleware = (requiredRole) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        const token = authHeader ? authHeader.split(' ')[1] : req.cookies.token;

        if (!token) {
            return res.status(401).json({ message: 'Access denied. No token provided.' });
        }

        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: 'Invalid or expired token.' });
            }

            req.user = decoded; // Stocke les infos utilisateur dans req.user

            console.log('Middleware auth - req.user:', req.user); // Vérifie ce que contient req.user pour déboguer

            if (requiredRole && req.user.role !== requiredRole) {
                return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
            }

            next();
        });
    };
};




// ROUTES
app.post('/Login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        if (rows.length === 0) {
            return res.status(401).json({ login: false, message: "Invalid credentials" });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ login: false, message: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id_user: user.id_user, role: user.role, username: user.username },
            JWT_SECRET, 
            { expiresIn: '1h' }
        );
        res.cookie('token', token, { httpOnly: true });

        res.json({ 
            login: true, 
            message: "Login successful", 
            userId: user.id_user, 
            userName: user.username, 
            email: user.email,
            role: user.role, 
            token 
        });
    } catch (error) {
        console.error("[ERROR] Login error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});





app.post('/Signup', async (req, res) => {
    const { username, email, password, selectedRole } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            [username, email, hashedPassword, selectedRole]
        );
        res.status(201).json({ message: "User created successfully", userId: result.insertId });
    } catch (error) {
        console.error("[ERROR] Signup error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Reservation route
app.post('/Reservations', authMiddleware('customer'), async (req, res) => {
    const { customerName, parkingId, vehicleType, vehicleRegistration, reservationDuration, numeberPhone, prix, total_prix } = req.body;

    try {
        const [result] = await db.query(
            "INSERT INTO Reservations (user_id, parking_lot_id, vehiculeType, matriculation, dureReservation, numeberuser, price, total_price, dateReservation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())",
            [customerName, parkingId, vehicleType, vehicleRegistration, reservationDuration, numeberPhone, prix, total_prix]
        );
        res.status(201).json({ success: true, result });
    } catch (error) {
        console.error("[ERROR] Reservation error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Add Parking Screen route
app.post('/AddParkingScreen', authMiddleware('manager'), async (req, res) => {
    const { name_parking, location, total_spaces, phone, price, manager_id } = req.body;

    try {
        const [result] = await db.query(
            "INSERT INTO parking_lots (name_parking, location, total_spaces, available_spaces, manager_id, tel, price, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())",
            [name_parking, location, total_spaces, total_spaces, manager_id, phone, price]
        );
        res.status(201).json({ success: true, result });
    } catch (error) {
        console.error("[ERROR] Add parking error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


app.get('/ParkingsScreen', authMiddleware(), async (req, res) => {
    const userId = req.user.id_user;
    const userRole = req.user.role;

    try {
        let query;
        let queryParams = [];

        if (userRole === 'manager') {
            // Retrieve only the parkings managed by the manager
            query = "SELECT * FROM parking_lots WHERE manager_id = ?";
            queryParams = [userId];
        } else if (userRole === 'customer') {
            // Retrieve all parkings
            query = "SELECT * FROM parking_lots";
        }

        // If the query is not set (e.g., user role is neither manager nor customer), return an error
        if (!query) {
            return res.status(403).json({ message: "Access denied." });
        }

        const [results] = await db.query(query, queryParams);
        res.status(200).json(results);
        console.log('parking', results);
        
    } catch (error) {
        console.error("[ERROR] Get parkings error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});




// Update Parking Screen route
app.put('/ParkingsScreen/:id', authMiddleware('customer'), async (req, res) => {
    const { id } = req.params;
    const { available_spaces } = req.body;

    try {
        await db.query('UPDATE parking_lots SET available_spaces = ? WHERE id_parking = ?', [available_spaces, id]);
        res.send({ success: true, message: 'Places disponibles mises à jour avec succès' });
    } catch (error) {
        console.error("[ERROR] Update parking error:", error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour des places disponibles' });
    }
});

// Get single Parking Screen route
app.get('/ParkingsScreen/:parkingId', authMiddleware(), async (req, res) => {
    const { parkingId } = req.params;

    try {
        const [results] = await db.query("SELECT * FROM parking_lots WHERE id_parking = ?", [parkingId]);
        if (results.length === 0) {
            return res.status(404).json({ message: "Parking not found" });
        }
        res.status(200).json(results[0]);
    } catch (error) {
        console.error("[ERROR] Get single parking error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Par exemple, renommez l'une des routes comme ceci



// Nouvelle route pour récupérer l'ID du manager basé sur l'ID du parking
app.get('/getManagerId/:parkingId', authMiddleware(), async (req, res) => {
    const { parkingId } = req.params;
    console.log("Requested parkingId:", parkingId); // Ajoutez ceci pour voir l'ID reçu

    try {
        const [results] = await db.query("SELECT manager_id FROM parking_lots WHERE id_parking = ?", [parkingId]);
        if (results.length === 0) {
            return res.status(404).json({ message: "Parking not found" });
        }
        res.status(200).json({ managerId: results[0].manager_id });
    } catch (error) {
        console.error("[ERROR] Get manager ID error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});



app.get('/user/:id', authMiddleware(), async (req, res) => {
    const { id } = req.params;

    try {
        const [results] = await db.query("SELECT * FROM users WHERE id_user = ?", [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(results[0]);
    } catch (error) {
        console.error("[ERROR] Get user error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Get messages route
// app.get('/messages', authMiddleware(), async (req, res) => {
//     const { sender_id, receiver_id } = req.query;

//     try {
//         const [results] = await db.query(
//             `SELECT * FROM messages 
//              WHERE (sender_id = ? AND receiver_id = ?) 
//                 OR (sender_id = ? AND receiver_id = ?)
//              ORDER BY sent_at ASC`,
//             [sender_id, receiver_id, receiver_id, sender_id]
//         );
//         res.status(200).json(results);
//     } catch (error) {
//         console.error("[ERROR] Get messages error:", error);
//         res.status(500).json({ message: "Internal server error" });
//     }
// });

app.get('/discussions/:id/messages', authMiddleware(), async (req, res) => {
    const discussionId = req.params.id;

    try {
        const sql = `
            SELECT m.id, m.sender_id, m.receiver_id, m.parking_lot_id, m.message_text, m.sent_at
            FROM messages m
            WHERE m.discussion_id = ?
            ORDER BY m.sent_at ASC
        `;
        console.log('Executing query:', sql);

        const [results] = await db.query(sql, [discussionId]);

        res.json(results);
    } catch (err) {
        console.error('Database query error:', err);
        res.status(500).json({ error: 'An unexpected error occurred.' });
    }
});


app.get('/discussion', authMiddleware(), async (req, res) => {
    try {
        const userId = req.user.id_user; // Ensure req.user contains the connected user
        console.log('User ID:', userId);
        
        const sql = `
            SELECT d.id_discution AS discussionId, 
                   d.id_part1 AS participant1Id, 
                   d.id_part2 AS participant2Id
            FROM discution d
            WHERE d.id_part1 = ? OR d.id_part2 = ?
        `;

        console.log('Executing query:', sql);

        // Use Promises to avoid nested callbacks
        const [results] = await db.query(sql, [userId, userId]);

        console.log('Query results:', results);
        res.json(results);
    } catch (error) {
        console.error('Error in discussion route:', error);
        res.status(500).json({ error: 'An unexpected error occurred while fetching discussions.' });
    }
});




async function InsertDiscution(id_part1, id_part2) {
    console.log(id_part2);
    
    const query = 'INSERT INTO discution(id_part1, id_part2) VALUES (?, ?);';
    const [result] = await db.query(query, [id_part1, id_part2]);
    return result.inserId;
}

async function checkDiscussionExists(id1, id2) {
    try {
        const [rows] = await db.query(
            `SELECT id_discution 
             FROM discution 
             WHERE (id_part1 = ? AND id_part2 = ?) OR (id_part1 = ? AND id_part2 = ?)`,
            [id1, id2, id2, id1]
        );

        if (rows.length > 0) {
            return rows[0].id_discution; // Return the found discussion ID
        } else {
            // If no discussion is found, create a new one
            const newDiscutID = await InsertDiscution(id1, id2);
            return newDiscutID; // Return the new discussion ID
        }
    } catch (error) {
        console.error('Error checking or creating discussion:', error);
        throw error; // Throw the error for handling elsewhere
    }
}





// POST /messages
app.post('/messages', authMiddleware(), async (req, res) => {
    const { sender_id, receiver_id, parking_lot_id, message_text } = req.body;
    const disctID = await checkDiscussionExists(sender_id, receiver_id);
    console.log('discusion',disctID);
    
    if (disctID) {
        try {
            await db.query(
                "INSERT INTO messages (sender_id, receiver_id, parking_lot_id, message_text, discussion_id) VALUES (?, ?, ?, ?, ?);",
                [sender_id, receiver_id, parking_lot_id, message_text, disctID]
            );
            res.status(201).json({ message: 'Message envoyé avec succès' });
        } catch (error) {
            console.error("[ERROR] Send message error:", error);
            res.status(500).json({ message: "Internal server error" })
        }
    } else if (!disctID){
        const DiscutID2 = await InsertDiscution(sender_id, receiver_id)
        console.log('discussId2',DiscutID2);
        
        try {
            await db.query(
                "INSERT INTO messages (sender_id, receiver_id, parking_lot_id, message_text, discussion_id) VALUES (?, ?, ?, ?, ?)",
                [sender_id, receiver_id, parking_lot_id, message_text, DiscutID2]
            );
            res.status(201).json({ message: 'Message envoyé avec succès' });
        } catch (error) {
            console.error("[ERROR] Send message error:", error);
            res.status(500).json({ message: "Internal server error" });
        }
    }
    
});

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // Listen for joining a parking lot chat
    socket.on('joinParkingLot', ({ parking_lot_id, user_id }) => {
        socket.join(parking_lot_id); // User joins a room associated with the parking lot
        console.log(`User ${user_id} joined parking lot ${parking_lot_id}`);
    });

    // Listen for sending messages
    socket.on('sendMessage', async (messageData) => {
        const { sender_id, receiver_id, parking_lot_id, message_text } = messageData;

        try {
            // Save message to the MySQL database
            const sql = 'INSERT INTO messages (sender_id, receiver_id, parking_lot_id, message_text) VALUES (?, ?, ?, ?)';
            await db.query(sql, [sender_id, receiver_id, parking_lot_id, message_text]);

            // Emit the message to the receiver in the parking lot
            io.to(parking_lot_id).emit('receiveMessage', {
                sender_id,
                receiver_id,
                parking_lot_id,
                message_text,
                sent_at: new Date()
            });
        } catch (error) {
            console.error("[ERROR] Send message error:", error);
        }
    });

    // Handle disconnections
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});


const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
