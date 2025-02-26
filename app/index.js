require("dotenv").config({ path: __dirname + "/../.env" });

const fs = require("fs");
const path = require("path");

// Ensure project structure is correct
if (!fs.existsSync(path.join(__dirname, "public/keys"))) {
  fs.mkdirSync(path.join(__dirname, "public/keys"));
}
if (!fs.existsSync(path.join(__dirname, "ssl"))) {
  fs.mkdirSync(path.join(__dirname, "ssl"));
}

// Setup basic express server
const express = require("express");
const app = express();

function envToBoolean(envVar) {
  const truthyValues = ['true', '1', 'yes', 'on'];
  const falsyValues = ['false', '0', 'no', 'off'];

  if (!envVar) return false; // Default to false if the variable is undefined or empty

  const normalized = envVar.trim().toLowerCase();
  
  if (truthyValues.includes(normalized)) return true;
  if (falsyValues.includes(normalized)) return false;

  throw new Error(`Invalid boolean environment variable value: "${envVar}"`);
}

// Get env variables
const useHttps = envToBoolean(process.env.USE_HTTPS);
const resetDB = envToBoolean(process.env.RESET_DB);
const resetKeys = envToBoolean(process.env.RESET_KEYS);

const port = process.env.PORT || 3000;

let server;

if (useHttps) {
  try {
    let options = {
      key: fs.readFileSync(__dirname + '/ssl/client-key.pem'),
      cert: fs.readFileSync(__dirname + '/ssl/client-cert.pem')
    };
    server = require("https").createServer(options, app);
  } catch (exception) {
    console.error("Failed to load SSL keys. Reason:");
    console.error(exception);
    console.info("Falling back to http.");
    server = require("http").createServer(app);
  }
} else {
  server = require("http").createServer(app);
}

const io = require("socket.io")(server);
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const subtle = crypto.webcrypto.subtle;

let con;

const Rooms = require("./rooms.js");
const Users = require("./users.js");

// Start server
server.listen(port, async () => {
  // DOCKER
  con = await mysql.createConnection({
    host: process.env.DATABASE_HOST || "localhost",
    user: process.env.MYSQL_USER || "admin",
    password: process.env.MYSQL_PASSWORD || "admin",
    database: process.env.MYSQL_DATABASE || "securechat",
    multipleStatements: true,
  });

  console.log("Connected to db");

  Rooms.setConnection(con);
  Users.setConnection(con);

  const basicState = require("./basicstate.js");

  const dropQuery =
    " \
    DROP TABLE IF EXISTS messages; \
    DROP TABLE IF EXISTS members; \
    DROP TABLE IF EXISTS users; \
    DROP TABLE IF EXISTS rooms; \
  ";

  const createSchemaQuery =
    " \
    \
    CREATE TABLE IF NOT EXISTS rooms( \
      id INT NOT NULL AUTO_INCREMENT, \
      name VARCHAR(50) NOT NULL, \
      description VARCHAR(200), \
      force_membership BOOLEAN DEFAULT 0,  \
      private BOOLEAN DEFAULT 0, \
      direct BOOLEAN DEFAULT 0, \
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
      PRIMARY KEY (id) \
    ); \
    CREATE TABLE IF NOT EXISTS users( \
      id INT NOT NULL AUTO_INCREMENT, \
      name VARCHAR(50) NOT NULL, \
      password VARCHAR(255), \
      active BOOLEAN DEFAULT 0, \
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
      PRIMARY KEY (id), \
      UNIQUE (name) \
    ); \
    CREATE TABLE IF NOT EXISTS members( \
      user_id INT NOT NULL, \
      room_id INT NOT NULL, \
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
      FOREIGN KEY (user_id) REFERENCES users(id), \
      FOREIGN KEY (room_id) REFERENCES rooms(id) \
    ); \
    CREATE TABLE IF NOT EXISTS messages( \
      id INT NOT NULL AUTO_INCREMENT, \
      user_id INT NOT NULL, \
      room_id INT NOT NULL, \
      message VARCHAR(500) NOT NULL, \
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, \
      PRIMARY KEY (id), \
      FOREIGN KEY (user_id) REFERENCES users(id), \
      FOREIGN KEY (room_id) REFERENCES rooms(id) \
    );";

  if (resetDB) {
    console.log("Dropping existing tables");
    await con.query(dropQuery);
    console.log("Dropped existing tables");
  }
  if (resetKeys) {
    console.log("Resetting keys");
    fs.readdir(path.join(__dirname, "public/keys"), (err, files) => {
      if (err) throw err;

      for (const file of files) {
        fs.unlink(path.join(__dirname, "public/keys", file), (err) => {
          if (err) throw err;
        });
      }
    });
    console.log("Keys reset");
  }
  console.log("Creating schema");
  await con.query(createSchemaQuery);

  console.log("Created schema");

  // Load application config/state
  await basicState.setup(Users, Rooms);

  console.log("Server listening on port %d", port);
});

// Routing for client-side files
app.use(express.static(path.join(__dirname, "public")));

///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(roomId, event, data) {
  io.to("room" + roomId).emit(event, data);
}

async function newUser(name) {
  const userId = await Users.addUser(name);
  const rooms = await Rooms.getForcedRooms();

  for (const room of rooms) {
    await addUserToRoom(userId, room.id);
  }

  return userId;
}

async function newRoom(name, user, options) {
  const roomId = await Rooms.addRoom(name, options);
  await addUserToRoom(user.id, roomId);
  return roomId;
}

async function newChannel(name, description, private, user) {
  return await newRoom(name, user, {
    description: description,
    private: private,
  });
}

async function newDirectRoom(user_a, user_b) {
  const roomId = await Rooms.addRoom(`Direct-${user_a.name}-${user_b.name}`, {
    direct: true,
    private: true,
  });

  await addUserToRoom(user_a.id, roomId);
  await addUserToRoom(user_b.id, roomId);

  return await Rooms.getRoom(roomId);
}

async function getDirectRoom(user_a, user_b) {
  let rooms = await Rooms.getRooms();
  rooms = rooms.filter(
    (r) =>
      r.direct &&
      ((r.members[0].name == user_a.name && r.members[1].name == user_b.name) ||
        (r.members[1].name == user_a.name && r.members[0].name == user_b.name))
  );

  if (rooms.length == 1) return rooms[0];
  else return await newDirectRoom(user_a, user_b);
}

function uint8ArrayToHexString(uint8Array) {
  return Array.prototype.map
    .call(uint8Array, (byte) => {
      return ("00" + byte.toString(16)).slice(-2);
    })
    .join("");
}

function hexStringToUint8Array(hexString) {
  const length = hexString.length / 2;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    const byteValue = parseInt(hexString.substr(i * 2, 2), 16);
    uint8Array[i] = byteValue;
  }

  return uint8Array;
}

async function refreshSymKey(roomId) {
  let room = await Rooms.getRoom(roomId);

  let symkey = await subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );

  let exportedSymKey = await subtle.exportKey("jwk", symkey);

  // the initialization vector for AES-GCM
  // has to be the same when encrypting and decrypting
  // doesn't have to be secret, according to
  // https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
  // so we generate it and store it along the key

  let iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  let ivString = uint8ArrayToHexString(iv);

  for (let member of room.members) {
    const keyPath = path.join(__dirname, `public/keys/${member.name}.key`);
    let info = JSON.parse(fs.readFileSync(keyPath));
    let clientKey = info["pub_key"];

    const encryptionAlgorithm = {
      name: "RSA-OAEP",
      hash: "SHA-256",
    };

    const rsaPublicKey = await subtle.importKey(
      "jwk",
      clientKey,
      encryptionAlgorithm,
      true,
      ["encrypt"]
    );

    const encryptedSymKey = await subtle.encrypt(
      encryptionAlgorithm,
      rsaPublicKey,
      new TextEncoder().encode(JSON.stringify(exportedSymKey))
    );

    let roomMessages = room.history.sort((a, b) =>
      a.id > b.id ? 1 : a.id < b.id ? -1 : 0
    ); //ordered by id
    let lastMessage = roomMessages[roomMessages.length - 1];

    let roomSessions = info["sessions"]
      .filter((ses) => ses.room == roomId)
      .sort((a, b) =>
        a.from_message > b.from_message
          ? 1
          : a.from_message < b.from_message
          ? -1
          : 0
      ); //ordered by from_message
    let lastSession = roomSessions[roomSessions.length - 1];

    // create new if lastMessage.id != lastSession.fromMessage, else replace last key
    // (no new message, all clients can just get another key)
    // no last key, add new key

    function ab2str(buf) {
      return String.fromCharCode.apply(null, new Uint8Array(buf));
    }

    let toStore = {
      room: roomId,
      from_message: lastMessage ? lastMessage.id : -1,
      sym_key: ab2str(encryptedSymKey),
      iv: ivString,
    };

    if (
      lastSession == undefined ||
      (lastSession != undefined &&
        lastMessage != undefined &&
        lastMessage.id != lastSession.fromMessage)
    ) {
      // add new key
      info["sessions"].push(toStore);
    } else {
      // replace last key
      let index = info["sessions"].findIndex(
        (ses) => ses.sym_key == lastSession.sym_key && ses.iv == lastSession.iv
      );
      if (index != -1) {
        info["sessions"][index] = toStore;
      } else {
        // impossible to reach, but just in case
        info["sessions"].push(toStore);
      }
    }

    // store new sessions
    fs.writeFileSync(keyPath, JSON.stringify(info));
    // send to user
    if (socketmap[member.name] && socketmap[member.name].connected) {
      socketmap[member.name].emit("update_session", info["sessions"]);
    }
  }
}

async function addUserToRoom(userId, roomId) {
  await Users.User.addSubscription(userId, roomId);

  // generate new symmetric key to encrypt messages in the room,
  // encrypt it with all the members' public keys, store them,
  // and send them to all active members' sockets
  refreshSymKey(roomId);

  sendToRoom(roomId, "update_user", {
    room: roomId,
    username: userId,
    action: "added",
    members: await Rooms.Room.getMembers(roomId),
  });
}

async function removeUserFromRoom(user, room) {
  await Users.User.removeSubscription(user.id, room.id);

  // generate new symmetric key to encrypt messages in the room,
  // encrypt it with all the members' public keys, store them,
  // and send them to all active members' sockets
  refreshSymKey(room.id);

  sendToRoom(room, "update_user", {
    room: room.id,
    username: user.name,
    action: "removed",
    members: await Rooms.Room.getMembers(room.id),
  });
}

async function addMessageToRoom(roomId, username, msg) {
  const room = await Rooms.getRoom(roomId);
  const user = await Users.getUser(username);
  msg.time = new Date().getTime();

  if (room && room != {}) {
    const msgId = await Rooms.Room.addMessage(user.id, roomId, msg.message);

    sendToRoom(roomId, "new message", {
      id: msgId,
      username: username,
      message: msg.message,
      room: msg.room,
      time: msg.time,
      direct: room.direct,
    });
  }
}

async function setUserActiveState(socket, username, state) {
  const user = await Users.getUser(username);

  if (user) {
    await Users.User.setActiveState(user.id, state);
  }

  socket.broadcast.emit("user_state_change", {
    username: username,
    active: state,
  });
}

///////////////////////////
// IO connection handler //
///////////////////////////

const socketmap = {};

io.on("connection", (socket) => {
  let userLoggedIn = false;
  let username = false;
  let CSRFToken = false;

  ///////////////
  //   auth    //
  ///////////////

  socket.on('config', () => {
    socket.emit('config', { clientId: process.env.GAUTH_CLIENT_ID || "", port: port, useHttps: useHttps, resetKeys: resetKeys });
  });

  socket.on("auth", async (code) => {
    // check if oauth2 is setup
    const clientId = process.env.GAUTH_CLIENT_ID || "";
    const clientSecret = process.env.GAUTH_CLIENT_SECRET || "";
    if (clientId == "" || clientSecret == " ") {
      socket.emit("auth", { error: "OAuth2 not setup" });
      return;
    }

    fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      body: JSON.stringify({
        code: code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: (useHttps ? "https": "http") + "://localhost:" + port,
        grant_type: "authorization_code",
      }),
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => response.json())
      .then((access_data) => {
        if (access_data.error) {
          socket.emit("auth", access_data);
          return;
        }

        fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
          headers: {
            Authorization: "Bearer " + access_data.access_token,
          },
        })
          .then((response) => response.json())
          .then((user_data) => {
            if (user_data.error) {
              socket.emit("auth", user_data);
              return;
            }

            // Auth success
            CSRFToken = access_data.access_token;
            // TODO: is the userid unique maybe?
            socket.emit("auth", { userId: user_data.sub.substr(0, 6), access_data: access_data });
          })
          .catch((error) => {
            console.log("Error retrieving user profile:", error);
            socket.emit("auth", { error: error });
            return;
          });
      })
      .catch((error) => {
        console.log("Error exchanging authorization code:", error);
        socket.emit("auth", { error: error });
        return;
      });
  });

  ///////////////////////
  // incomming message //
  ///////////////////////

  socket.on("new message", async (msg) => {
    if (userLoggedIn) {
      if (!CSRFToken || msg.CSRFToken != CSRFToken) {
        return;
      }
      await addMessageToRoom(msg.room, username, msg);
    }
  });

  /////////////////////////////
  // request for direct room //
  /////////////////////////////

  socket.on("request_direct_room", async (req) => {
    if (userLoggedIn) {
      if (!CSRFToken || req.CSRFToken != CSRFToken) {
        return;
      }
      const user_a = await Users.getUser(req.to);
      const user_b = await Users.getUser(username);

      if (user_a && user_b) {
        const room = await getDirectRoom(user_a, user_b);
        const roomCID = "room" + room.id;
        socket.join(roomCID);
        if (socketmap[user_a.name]) socketmap[user_a.name].join(roomCID);

        socket.emit("update_room", {
          room: room,
          moveto: true,
        });
      }
    }
  });

  socket.on("add_channel", async (req) => {
    if (userLoggedIn) {
      if (!CSRFToken || req.CSRFToken != CSRFToken) {
        return;
      }
      const user = await Users.getUser(username);
      let roomId = await newChannel(
        req.name,
        req.description,
        req.private,
        user
      );

      let room = await Rooms.getRoom(roomId);

      const roomCID = "room" + room.id;
      socket.join(roomCID);

      socket.emit("update_room", {
        room: room,
        moveto: true,
      });

      if (!room.private) {
        let publicChannels = await Rooms.getRooms();
        publicChannels = publicChannels.filter((r) => !r.direct && !r.private);
        socket.broadcast.emit("update_public_channels", {
          publicChannels: publicChannels,
        });
      }
    }
  });

  socket.on("join_channel", async (req) => {
    if (userLoggedIn) {
      if (!CSRFToken || req.CSRFToken != CSRFToken) {
        return;
      }

      const user = await Users.getUser(username);
      const room = await Rooms.getRoom(req.id);

      if (!room.direct && !room.private) {
        await addUserToRoom(user, room);

        const roomCID = "room" + room.id;
        socket.join(roomCID);

        socket.emit("update_room", {
          room: room,
          moveto: true,
        });
      }
    }
  });

  socket.on("add_user_to_channel", async (req) => {
    if (userLoggedIn) {
      if (!CSRFToken || req.CSRFToken != CSRFToken) {
        return;
      }
      const user = await Users.getUser(req.user);
      const room = await Rooms.getRoom(req.channel);

      if (!room.direct) {
        await addUserToRoom(user.id, room.id);

        if (socketmap[user.name]) {
          const roomCID = "room" + room.id;
          socketmap[user.name].join(roomCID);

          socketmap[user.name].emit("update_room", {
            room: room,
            moveto: false,
          });
        }
      }
    }
  });

  socket.on("leave_channel", async (req) => {
    if (!CSRFToken || req.CSRFToken != CSRFToken) {
      return;
    }

    if (userLoggedIn) {
      const user = await Users.getUser(username);
      const room = await Rooms.getRoom(req.id);

      if (!room.direct && !room.forceMembership) {
        await removeUserFromRoom(user, room);

        const roomCID = "room" + room.id;
        socket.leave(roomCID);

        socket.emit("remove_room", {
          room: room.id,
        });
      }
    }
  });

  ///////////////
  //   crypto  //
  ///////////////

  socket.on("pub_key", async (username, pub_key) => {
    let pub_key_path = path.join(__dirname, `public/keys/${username}.key`);
    try {
      if (fs.existsSync(pub_key_path)) {
        let info = JSON.parse(fs.readFileSync(pub_key_path));
        // session must be reset, since we can't decode the old ones
        // after the private/public key pair is updated

        info["pub_key"] = pub_key;
        // info["sessions"] = [];
        fs.writeFileSync(pub_key_path, JSON.stringify(info));
        
        //refresh room keys
        // let rooms = await Users.User.getSubscriptions(username);
        // for (let room of rooms) {
        //   refreshSymKey(room.room_id);
        // }
      } else {
        let info = { pub_key: pub_key, sessions: [] };
        fs.writeFileSync(pub_key_path, JSON.stringify(info));
      }
    } catch (err) {
      console.error(err);
    }
    onJoin(username);
  });

  ///////////////
  // user join //
  ///////////////

  async function onJoin(p_username) {
    if (userLoggedIn) {
      return;
    }
    if (!p_username) {
      return;
    }
    
    username = p_username;

    userLoggedIn = true;
    socketmap[username] = socket;

    // send updated list of sessions to client
    // public key is stored at this point
    const keyPath = path.join(__dirname, `public/keys/${username}.key`);
    let info = JSON.parse(fs.readFileSync(keyPath));

    socket.emit("update_session", info["sessions"], async (username) => {
      //callback to continue login process after the session has been updated
      let user = await Users.getUser(username);
      if (!user) {
        user = await newUser(username);
      }

      let rooms = await Users.User.getSubscriptions(username);

      let finalRooms = [];

      for (const room of rooms) {
        socket.join("room" + room.room_id);
        let fRoom = await Rooms.getRoom(room.room_id);
        finalRooms.push(fRoom);
      }

      const bRooms = await Rooms.getRooms();
      const publicChannels = bRooms.filter((r) => !r.direct && !r.private);

      const users = await Users.getUsers();
      socket.emit("login", {
        users: users.map((u) => ({ username: u.name, active: u.active })),
        rooms: finalRooms,
        publicChannels: publicChannels,
      });

      await setUserActiveState(socket, username, true);
    });
  }

  socket.on("join", async (p_username) => {
    onJoin(p_username);
  });

  ////////////////
  // reconnects //
  ////////////////

  socket.on("reconnect", async () => {
    if (userLoggedIn) await setUserActiveState(socket, username, true);
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on("disconnect", async () => {
    if (userLoggedIn) await setUserActiveState(socket, username, false);
  });
});
