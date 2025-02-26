module.exports = {
    setup: async (Users, Rooms) => {
        await Rooms.addRoom("random", { forceMembership: true, description: "Random!", noDuplicate: true });
        await Rooms.addRoom("general", { forceMembership: true, description: "interesting things", noDuplicate: true });
        await Rooms.addRoom("private", { forceMembership: true, description: "some very private channel", private: true, noDuplicate: true });
    }
}
