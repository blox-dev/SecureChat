class User {
    static con;

    static async createUser(name) {
        // Insert user into DB if it doesn't exist
        const existsQuery = 'SELECT name FROM users where name = ?'
        const [rows] = await User.con.query(existsQuery, [name])
        if (!rows.length) {
            const query = 'INSERT INTO users (name, active) VALUES (?, 1)'
            const [user] = await User.con.query(query, [name])
            return user.insertId
        }
    }

    static async getSubscriptions(userName) {
        // select user subscriptions from DB
        const query = 'SELECT room_id FROM members join users ON members.user_id = users.id WHERE users.name = ?'
        const [rooms] = await User.con.query(query, [userName]);
        return rooms;
    }

    static async addSubscription(userId, roomId) {
        // add subscription if doesn't exist into DB
        const existsQuery = 'SELECT * FROM members WHERE user_id = ? AND room_id = ?'
        const [rows] = await User.con.query(existsQuery, [userId, roomId])
        if (!rows.length) {
            const query = 'INSERT INTO members (user_id, room_id) VALUES (?, ?)'
            await User.con.query(query, [userId, roomId])
        }
    }

    static async removeSubscription(userId, roomId) {
        // remove subscription from DB
        const query = 'DELETE FROM members WHERE user_id = ? AND room_id = ?'
        await User.con.query(query, [userId, roomId])
    }

    static async setActiveState(userId, active) {
        const query = 'UPDATE users SET active = ? WHERE id = ?'
        await User.con.query(query, [active, userId])
    }

}

module.exports = {
    User,
    addUser: async (name) => {
        return await User.createUser(name)
    },

    getUser: async (userName) => {
        const query = 'SELECT * FROM users WHERE name = ?';
        const [user] = await User.con.query(query, [userName]);
        return user[0];
    },

    getUsers: async () => {
        const query = 'SELECT * FROM users';
        const [users] = await User.con.query(query);
        return users;
    },

    setConnection: (con) => {
        User.con = con
    }
}
