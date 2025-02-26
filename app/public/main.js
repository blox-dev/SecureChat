$(function () {
  // OAUTH2 authentication

  async function isAuthenticated() {
    const token = localStorage.getItem("access_token");

    if (token == null) {
      return false;
    }

    try {
      const resp = await fetch(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        {
          headers: {
            Authorization: "Bearer " + token,
          },
        }
      );
      const data = await resp.json();

      if (data.error) {
        console.log("Error retrieving user profile:", data.error_description);
        return false;
      }

      // Auth success
      return data.sub;
    } catch (error) {
      console.log("Error retrieving user profile:", error);
      return false;
    }
  }

  async function toggleContentVisibility() {
    const mainContent = document.getElementById("main");
    const authDialog = document.getElementById("auth");

    if (await isAuthenticated()) {
      mainContent.style.display = "flex";
      authDialog.style.display = "none";
    } else {
      console.log("Not authenticated, removing access token");
      localStorage.removeItem("access_token");
      mainContent.style.display = "none";
      authDialog.style.display = "flex";
    }
  }

  async function handleLogin() {
    const socket = io();
    socket.emit('config');
    
    socket.on('config', (config) => {
      const clientId = config.clientId;
      const port = config.port;
      const useHttps = config.useHttps;

      if (!clientId) {
        console.error("Google Auth Client ID not found");
        alert("Google Auth Client ID not setup, authentication failed");
        return;
      }
      
      const url =
        "https://accounts.google.com/o/oauth2/v2/auth?" +
        "client_id=" + clientId + 
        "&redirect_uri=" + (useHttps ? "https" : "http") + "%3A%2F%2Flocalhost%3A" + port +
        "&response_type=code" +
        "&scope=openid%20email%20profile";
      window.location.href = url;
    });
  }

  function handleLogout() {
    localStorage.removeItem("access_token");
    window.clearTimeout(handleLogout);
    handleAuthentication();
  }

  function handleOAuthCallback(code) {
    const socket = io();
    // socket.removeAllListeners();

    socket.emit("auth", code);

    socket.on("auth", (data) => {
      if (data.error) {
        console.log("Server error: ", data);
        return;
      }

      localStorage.setItem("access_token", data.access_data.access_token);

      // expire the token automatically
      window.setTimeout(handleLogout, data.access_data.expires_in * 1000);

      toggleContentVisibility();

      // remove url parameters so it doesn't reattempt logging in
      window.history.replaceState({}, document.title, "/");

      showApp(data.userId, socket);
    });
  }

  async function handleAuthentication() {
    await toggleContentVisibility();

    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");

    const username = await isAuthenticated();
    if (username) {
      showApp(username);
    } else if (code) {
      handleOAuthCallback(code);
    } else {
      const loginButton = $("#login-button");
      loginButton.on("click", handleLogin);
    }
  }

  // Run initial setup on page load
  handleAuthentication();

  function showApp(username, socket) {
    // Initialize variables
    const $window = $(window);
    const $messages = $(".messages"); // Messages area
    const $inputMessage = $("#input-message"); // Input message input box
    const $usernameLabel = $("#user-name");
    const $roomList = $("#room-list");
    const $userList = $("#user-list");
    const $logoutButton = $("#logout-button");
    $logoutButton.on("click", handleLogout);

    // sanitization
    // https://stackoverflow.com/a/822486
    function sanitize(html) {
      let doc = new DOMParser().parseFromString(html, "text/html");
      return doc.body.textContent || "";
    }

    if (!username) {
      // shouldn't happen
      username = "username";
    }
    $usernameLabel.text(username);

    let connected = false;

    if (socket == null) {
      socket = io();
    }

    let modalShowing = false;

    $("#addChannelModal")
      .on("hidden.bs.modal", () => (modalShowing = false))
      .on("show.bs.modal", () => (modalShowing = true));

    ///////////////
    // User List //
    ///////////////

    let users = {};

    function updateUsers(p_users) {
      p_users.forEach((u) => (users[u.username] = u));
      updateUserList();
    }

    function updateUser(username, active) {
      if (!users[username]) users[username] = { username: username };

      users[username].active = active;

      updateUserList();
    }

    function updateUserList() {
      const $uta = $("#usersToAdd");
      $uta.empty();

      $userList.empty();
      for (let [un, user] of Object.entries(users)) {
        if (username !== user.username)
          $userList.append(`
          <li onclick="setDirectRoom(this)" data-direct="${
            user.username
          }" class="${user.active ? "online" : "offline"}">${user.username}</li>
        `);
        // append it also to the add user list
        $uta.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="addToChannel('${user.username}')">${user.username}</button>
        `);
      }
    }

    ///////////////
    // Room List //
    ///////////////

    let rooms = [];

    function updateRooms(p_rooms) {
      rooms = p_rooms;
      updateRoomList();
    }

    function updateRoom(room) {
      let i = rooms.findIndex((r) => r.id == room.id);
      if (i != -1) {
        rooms[i] = room;
      } else {
        rooms.push(room);
      }
      updateRoomList();
    }

    function removeRoom(id) {
      let i = rooms.findIndex((r) => r.id == id);
      if (i != -1) {
        rooms.splice(i, 1);
      }
      updateRoomList();
    }

    function updateRoomList() {
      $roomList.empty();
      rooms.forEach((r) => {
        if (!r.direct)
          $roomList.append(`
          <li onclick="setRoom(${r.id})"  data-room="${r.id}" class="${
            r.private ? "private" : "public"
          }">${r.name}</li>
        `);
      });
    }

    function updateChannels(channels) {
      const c = $("#channelJoins");

      c.empty();
      channels.forEach((r) => {
        if (!rooms[r.id])
          c.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="joinChannel(${r.id})">${r.name}</button>
        `);
      });
    }

    //////////////
    // Chatting //
    //////////////

    let currentRoom = false;

    async function setRoom(id) {
      let oldRoom = currentRoom;
      let i = rooms.findIndex((r) => r.id == id);
      const room = rooms[i];
      currentRoom = room;

      $messages.empty();
      for (let message of room.history) {
        await addChatMessage(message);
      }

      $userList.find("li").removeClass("active");
      $roomList.find("li").removeClass("active");

      if (room.direct) {
        const idx = room.members.indexOf(username) == 0 ? 1 : 0;
        const user = room.members[idx];
        setDirectRoomHeader(user.name);

        $userList
          .find(`li[data-direct="${user}"]`)
          .addClass("active")
          .removeClass("unread")
          .attr("data-room", room.id);
      } else {
        $("#channel-name").text("#" + room.name);
        $("#channel-description").text(
          `👤 ${room.members.length} | ${room.description}`
        );
        $roomList
          .find(`li[data-room=${room.id}]`)
          .addClass("active")
          .removeClass("unread");
      }

      $(".roomAction").css(
        "visibility",
        room.direct || room.forceMembership ? "hidden" : "visible"
      );
    }
    window.setRoom = setRoom;

    function setDirectRoomHeader(user) {
      $("#channel-name").text(user);
      $("#channel-description").text(`Direct message with ${user}`);
    }

    function setToDirectRoom(user) {
      setDirectRoomHeader(user);
      const token = localStorage.getItem("access_token");
      socket.emit("request_direct_room", { to: user, CSRFToken: token });
    }

    window.setDirectRoom = async (el) => {
      const user = el.getAttribute("data-direct");
      const room = el.getAttribute("data-room");

      if (room) {
        await setRoom(parseInt(room));
      } else {
        setToDirectRoom(user);
      }
    };

    // https://stackoverflow.com/a/47431969

    function ab2str(buf) {
      return String.fromCharCode.apply(null, new Uint8Array(buf));
    }

    function str2ab(str) {
      let buf = new ArrayBuffer(str.length); // 2 bytes for each char
      let bufView = new Uint8Array(buf);
      for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
      }
      return buf;
    }

    // https://stackoverflow.com/a/55200387

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

    async function sendMessage() {
      let message = sanitize($inputMessage.val());

      if (message && connected && currentRoom !== false) {
        $inputMessage.val("");

        //encrypt message with latest symkey for the room
        let sessions = JSON.parse(localStorage.getItem("sessions"));
        let roomSessions = sessions[username]
          .filter((sess) => sess.room == currentRoom.id)
          .sort((a, b) =>
            a.from_message > b.from_message
              ? 1
              : a.from_message < b.from_message
              ? -1
              : 0
          );

        const lastSession = roomSessions[roomSessions.length - 1];

        let key = await window.crypto.subtle.importKey(
          "jwk",
          lastSession.sym_key,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );

        const encryptionAlgorithm = {
          name: "AES-GCM",
          iv: hexStringToUint8Array(lastSession.iv),
          tagLength: 128,
        };

        let encMessageBuffer = await window.crypto.subtle.encrypt(
          encryptionAlgorithm,
          key,
          str2ab(message)
        );

        const encMessage = ab2str(encMessageBuffer);

        const token = localStorage.getItem("access_token");

        const msg = {
          CSRFToken: token,
          username: username,
          message: encMessage,
          room: currentRoom.id,
        };

        //addChatMessage(msg);
        socket.emit("new message", msg);
      }
    }

    async function addChatMessage(msg) {
      let time = new Date(msg.time).toLocaleTimeString("en-US", {
        hour12: false,
        hour: "numeric",
        minute: "numeric",
      });

      // decrypt message using symmetric key from session
      let sessions = JSON.parse(localStorage.getItem("sessions")) || {};

      // if no suitable decryption key is available, then the message cannot
      // be decrypted, so we skip it.

      if (!sessions[username]) {
        return;
      }

      let roomSessions = sessions[username]
        .filter((sess) => sess.room == msg.room) // only in current room
        .filter((sess) => sess.from_message < msg.id) // older than the current message
        .sort((a, b) =>
          a.from_message > b.from_message
            ? 1
            : a.from_message < b.from_message
            ? -1
            : 0
        ); //ordered by from_message

      if (roomSessions.length == 0) {
        return;
      }

      const lastSession = roomSessions[roomSessions.length - 1];

      let symKey = await window.crypto.subtle.importKey(
        "jwk",
        lastSession.sym_key,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const iv = hexStringToUint8Array(lastSession.iv);

      const encryptionAlgorithm = {
        name: "AES-GCM",
        iv: iv,
        tagLength: 128,
      };

      let decBuffer = undefined;
      try {
        // will fail when decrypting a message which was sent
        // after the user left a room and before he rejoined
        decBuffer = await window.crypto.subtle.decrypt(
          encryptionAlgorithm,
          symKey,
          str2ab(msg.message)
        );
      } catch (error) {
        // ignore the error
      }

      if(decBuffer == undefined) {
        return;
      }

      const decMessage = ab2str(decBuffer);

      $messages.append(`
      <div class="message">
        <div class="message-avatar"></div>
        <div class="message-textual">
          <span class="message-user">${msg.username}</span>
          <span class="message-time">${time}</span>
          <span class="message-content">${decMessage}</span>
        </div>
      </div>
    `);

      $messages[0].scrollTop = $messages[0].scrollHeight;
    }

    function messageNotify(msg) {
      if (msg.direct)
        $userList.find(`li[data-direct="${msg.username}"]`).addClass("unread");
      else $roomList.find(`li[data-room=${msg.room}]`).addClass("unread");
    }

    function addChannel() {
      const name = sanitize($("#inp-channel-name").val());
      const description = sanitize($("#inp-channel-description").val());
      const private = $("#inp-private").is(":checked");
      const token = localStorage.getItem("access_token");

      socket.emit("add_channel", {
        CSRFToken: token,
        name: name,
        description: description,
        private: private,
      });
    }
    window.addChannel = addChannel;

    function joinChannel(id) {
      const token = localStorage.getItem("access_token");
      socket.emit("join_channel", { id: id , CSRFToken: token});
    }
    window.joinChannel = joinChannel;

    function addToChannel(user) {
      const token = localStorage.getItem("access_token");
      socket.emit("add_user_to_channel", {
        CSRFToken: token,
        channel: currentRoom.id,
        user: user,
      });
    }
    window.addToChannel = addToChannel;

    function leaveChannel() {
      const token = localStorage.getItem("access_token");
      socket.emit("leave_channel", { id: currentRoom.id, CSRFToken: token });
    }
    window.leaveChannel = leaveChannel;

    /////////////////////
    // Keyboard events //
    /////////////////////

    $window.keydown(async (event) => {
      if (modalShowing) return;

      // Autofocus the current input when a key is typed
      if (!(event.ctrlKey || event.metaKey || event.altKey)) {
        $inputMessage.focus();
      }

      // When the client hits ENTER on their keyboard
      if (event.which === 13) {
        await sendMessage();
      }

      // don't add newlines
      if (event.which === 13 || event.which === 10) {
        event.preventDefault();
      }
    });

    ///////////////////
    // server events //
    ///////////////////

    // Whenever the server emits -login-, log the login message
    socket.on("login", async (data) => {
      connected = true;

      updateUsers(data.users);
      updateRooms(data.rooms);
      updateChannels(data.publicChannels);

      if (data.rooms.length > 0) {
        await setRoom(data.rooms[0].id);
      }
    });

    socket.on("update_public_channels", (data) => {
      updateChannels(data.publicChannels);
    });

    // Whenever the server emits 'new message', update the chat body
    socket.on("new message", (msg) => {
      const roomId = msg.room;
      const i = rooms.findIndex((r) => r.id == roomId);
      const room = rooms[i];
      if (room) {
        room.history.push(msg);
      }

      if (roomId == currentRoom.id) addChatMessage(msg);
      else messageNotify(msg);
    });

    socket.on("update_user", async (data) => {
      const roomId = data.room;
      const i = rooms.findIndex((r) => r.id == roomId);
      const room = rooms[i];
      if (room) {
        room.members = data.members;

        if (room === currentRoom) {
          await setRoom(data.room);
        }
      }
    });

    socket.on("user_state_change", (data) => {
      updateUser(data.username, data.active);
    });

    socket.on("update_room", async (data) => {
      updateRoom(data.room);
      if (data.moveto) { 
        await setRoom(data.room.id);
      }
    });

    socket.on("remove_room", async (data) => {
      removeRoom(data.room);
      if (currentRoom.id == data.room) {
        await setRoom(rooms[0].id);
      }
    });

    ////////////////////////
    // Server cypto stuff //
    ////////////////////////

    socket.on("update_session", async (data, callback) => {
      let sessions = JSON.parse(localStorage.getItem("sessions")) || {};

      // decrypt symkeys
      for (let session of data) {
        const decryptionAlgorithm = {
          name: "RSA-OAEP",
          hash: "SHA-256",
        };

        const xd = session["sym_key"];
        let symk = await window.crypto.subtle.decrypt(
          decryptionAlgorithm,
          privateKey,
          str2ab(xd)
        );
        session["sym_key"] = JSON.parse(ab2str(symk));
      }

      sessions[username] = data;
      localStorage.setItem("sessions", JSON.stringify(sessions));

      if (callback) {
        // continue login process, if necessary
        callback(username);
      }
    });

    ////////////////
    // Connection //
    ////////////////

    socket.on("disconnect", () => {
      // handleLogout();
    });

    socket.on("reconnect", () => {
      // join
      socket.emit("join", username);
    });

    socket.on("reconnect_error", () => {});

    let privateKey = undefined;

    //start here
    async function joinServer() {
      // create public-private pair key if it doesn't exist
      let keys = JSON.parse(localStorage.getItem("keys")) || {};
      if (keys[username] == undefined) {
        let keyPair = await window.crypto.subtle.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          },
          true,
          ["encrypt", "decrypt"]
        );

        privateKey = keyPair.privateKey;

        const exportedPublicKey = await window.crypto.subtle.exportKey(
          "jwk",
          keyPair.publicKey
        );
        const exportedPrivateKey = await window.crypto.subtle.exportKey(
          "jwk",
          keyPair.privateKey
        );

        // store private key in localStorage
        // TODO: encrypt with user password maybe?
        let setKeys = keys || {};
        setKeys[username] = exportedPrivateKey;
        localStorage.setItem("keys", JSON.stringify(setKeys));

        // send public key to server
        socket.emit("pub_key", username, exportedPublicKey);
      } else {
        const keys = JSON.parse(localStorage.getItem("keys"));
        // privateKey = keys[username];

        privateKey = await window.crypto.subtle.importKey(
          "jwk",
          keys[username],
          {
            name: "RSA-OAEP",
            hash: "SHA-256",
          },
          true,
          ["decrypt"]
        );
        socket.emit("join", username);
      }
    }

    joinServer();
  }
});
