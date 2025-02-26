class Room {
    static con;

    static async createRoom(name, options) {
        const description = options.description || "";
      
        const forceMembership = !!options.forceMembership;
        const isPrivate         = !!options.private;
        const direct          = !!options.direct;
        const noDuplicate = !!options.noDuplicate;

        if(noDuplicate) {
            const selectQuery = 'SELECT * FROM rooms WHERE name = ? AND description = ? AND force_membership = ? AND private = ? AND direct = ?'
            const [room] = await Room.con.query(selectQuery, [name, description, forceMembership, isPrivate, direct]);
            if(room.length) {
                return room[0].id;
            }
        }
        const query = 'INSERT INTO rooms (name, description, force_membership, private, direct) \
            VALUES (?, ?, ?, ?, ?)'
        const [room] = await Room.con.query(query, [name, description, forceMembership, isPrivate, direct]);
        return room.insertId;
    }

    static async getMembers(roomId) {
        const query = 'SELECT users.* FROM rooms JOIN members ON rooms.id = members.room_id JOIN users ON members.user_id = users.id WHERE rooms.id = ?'
        const [users] = await Room.con.query(query, [roomId]);
        return users;
    }

    static async getMemberCount(roomId){
        const query = 'SELECT user_id FROM rooms JOIN members ON rooms.id = members.room_id WHERE rooms.id = ?'
        const [users] = await Room.con.query(query, [roomId]);
        return users.length;
    }

    // TODO: remove, same functionality in users.addSubscription
    addMember(user) {
        if (this.members.indexOf(user.name) === -1)
            this.members.push(user.name);
    }

    // TODO: remove, same functionality in users.removeSubscription
    removeMember(user) {        
        const idx = this.members.indexOf(user.name);
        if (idx >= 0)
            this.members.splice(idx, 1);
    }

    static async getHistory(roomId) {
        const query = 'SELECT * FROM messages WHERE room_id = ? ORDER BY id'
        const [messages] = await Room.con.query(query, [roomId]);

        //trickery for compat
        for (let message of messages) {
            //set time
            message.time = message.created_at.getTime();

            // set username
            const query2 = 'SELECT name FROM users WHERE id = ?'
            const [users] = await Room.con.query(query2, [message.user_id])

            message.username = users[0].name;

            // set direct
            const query3 = 'SELECT direct FROM rooms WHERE id = ?'
            const [room] = await Room.con.query(query3, [roomId])

            message.room = roomId;
            message.direct = room[0].direct;
        }
        return messages;
    }

    static async addMessage(userId, roomId, msg) {
        const query = 'INSERT INTO messages (user_id, room_id, message) VALUES (?, ?, ?)'
        const [message] = await Room.con.query(query, [userId, roomId, msg]);
        return message.insertId;
    }
}

module.exports = {
    Room,
    addRoom: async (name, options) => {
        return await Room.createRoom(name, options);
    },

    getRooms: async () => {
        query = 'SELECT * FROM rooms';
        const [rooms] = await Room.con.query(query);
        for (let room of rooms) {
            const history = await Room.getHistory(room.id);
            room['history'] = history;
            // set room members
            const members = await Room.getMembers(room.id);
            room['members'] = members;
        }
        return rooms;
    },

    getForcedRooms: async () => {
        // get rooms from db
        const query = "SELECT id FROM rooms WHERE force_membership = 1"
        const [rooms] = await Room.con.query(query);
        return rooms;
        // return rooms.map(m => m.id)
    },

    getRoom: async (roomId) => {
        query = 'SELECT * FROM rooms WHERE id = ?';
        let [room] = await Room.con.query(query, [roomId]);
        room = room[0]
        //set room history
        const history = await Room.getHistory(roomId);
        room['history'] = history;
        // set room members
        const members = await Room.getMembers(roomId);
        room['members'] = members;

        return room;
    },

    setConnection: (con) => {
        Room.con = con
    }
}
