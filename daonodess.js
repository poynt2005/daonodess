(function (w) {
    var crypto = require("crypto");
    var net = require("net");
    var http = require("http");
    var WebSocket = require('ws');

    function encryptLib() {
        var EVP_BytesToKey, Encryptor, bytes_to_key_results, cachedTables, create_rc4_md5_cipher, getTable, int32Max, method_supported, substitute;

        var merge_sort = merge_sortLib().merge_sort;

        int32Max = Math.pow(2, 32);

        cachedTables = {};

        getTable = function (key) {
            var ah, al, decrypt_table, hash, i, md5sum, result, table;
            if (cachedTables[key]) {
                return cachedTables[key];
            }
            console.log("calculating ciphers");
            table = new Array(256);
            decrypt_table = new Array(256);
            md5sum = crypto.createHash("md5");
            md5sum.update(key);
            hash = new Buffer(md5sum.digest(), "binary");
            al = hash.readUInt32LE(0);
            ah = hash.readUInt32LE(4);
            i = 0;
            while (i < 256) {
                table[i] = i;
                i++;
            }
            i = 1;
            while (i < 1024) {
                table = merge_sort(table, function (x, y) {
                    return ((ah % (x + i)) * int32Max + al) % (x + i) - ((ah % (y + i)) * int32Max + al) % (y + i);
                });
                i++;
            }
            i = 0;
            while (i < 256) {
                decrypt_table[table[i]] = i;
                ++i;
            }
            result = [table, decrypt_table];
            cachedTables[key] = result;
            return result;
        };

        substitute = function (table, buf) {
            var i;
            i = 0;
            while (i < buf.length) {
                buf[i] = table[buf[i]];
                i++;
            }
            return buf;
        };

        bytes_to_key_results = {};

        EVP_BytesToKey = function (password, key_len, iv_len) {
            var count, d, data, i, iv, key, m, md5, ms;
            if (bytes_to_key_results[password + ":" + key_len + ":" + iv_len]) {
                return bytes_to_key_results[password + ":" + key_len + ":" + iv_len];
            }
            m = [];
            i = 0;
            count = 0;
            while (count < key_len + iv_len) {
                md5 = crypto.createHash('md5');
                data = password;
                if (i > 0) {
                    data = Buffer.concat([m[i - 1], password]);
                }
                md5.update(data);
                d = md5.digest();
                m.push(d);
                count += d.length;
                i += 1;
            }
            ms = Buffer.concat(m);
            key = ms.slice(0, key_len);
            iv = ms.slice(key_len, key_len + iv_len);
            bytes_to_key_results[password] = [key, iv];
            return [key, iv];
        };

        method_supported = {
            'aes-128-cfb': [16, 16],
            'aes-192-cfb': [24, 16],
            'aes-256-cfb': [32, 16],
            'bf-cfb': [16, 8],
            'camellia-128-cfb': [16, 16],
            'camellia-192-cfb': [24, 16],
            'camellia-256-cfb': [32, 16],
            'cast5-cfb': [16, 8],
            'des-cfb': [8, 8],
            'idea-cfb': [16, 8],
            'rc2-cfb': [16, 8],
            'rc4': [16, 0],
            'rc4-md5': [16, 16],
            'seed-cfb': [16, 16]
        };

        create_rc4_md5_cipher = function (key, iv, op) {
            var md5, rc4_key;
            md5 = crypto.createHash('md5');
            md5.update(key);
            md5.update(iv);
            rc4_key = md5.digest();
            if (op === 1) {
                return crypto.createCipheriv('rc4', rc4_key, '');
            } else {
                return crypto.createDecipheriv('rc4', rc4_key, '');
            }
        };

        Encryptor = (function () {
            function Encryptor(key1, method1) {
                var ref;
                this.key = key1;
                this.method = method1;
                this.iv_sent = false;
                if (this.method === 'table') {
                    this.method = null;
                }
                if (this.method != null) {
                    this.cipher = this.get_cipher(this.key, this.method, 1, crypto.randomBytes(32));
                } else {
                    ref = getTable(this.key), this.encryptTable = ref[0], this.decryptTable = ref[1];
                }
            }

            Encryptor.prototype.get_cipher_len = function (method) {
                var m;
                method = method.toLowerCase();
                m = method_supported[method];
                return m;
            };

            Encryptor.prototype.get_cipher = function (password, method, op, iv) {
                var iv_, key, m, ref;
                method = method.toLowerCase();
                password = new Buffer(password, 'binary');
                m = this.get_cipher_len(method);
                if (m != null) {
                    ref = EVP_BytesToKey(password, m[0], m[1]), key = ref[0], iv_ = ref[1];
                    if (iv == null) {
                        iv = iv_;
                    }
                    if (op === 1) {
                        this.cipher_iv = iv.slice(0, m[1]);
                    }
                    iv = iv.slice(0, m[1]);
                    if (method === 'rc4-md5') {
                        return create_rc4_md5_cipher(key, iv, op);
                    } else {
                        if (op === 1) {
                            return crypto.createCipheriv(method, key, iv);
                        } else {
                            return crypto.createDecipheriv(method, key, iv);
                        }
                    }
                }
            };

            Encryptor.prototype.encrypt = function (buf) {
                var result;
                if (this.method != null) {
                    result = this.cipher.update(buf);
                    if (this.iv_sent) {
                        return result;
                    } else {
                        this.iv_sent = true;
                        return Buffer.concat([this.cipher_iv, result]);
                    }
                } else {
                    return substitute(this.encryptTable, buf);
                }
            };

            Encryptor.prototype.decrypt = function (buf) {
                var decipher_iv, decipher_iv_len, result;
                if (this.method != null) {
                    if (this.decipher == null) {
                        decipher_iv_len = this.get_cipher_len(this.method)[1];
                        decipher_iv = buf.slice(0, decipher_iv_len);
                        this.decipher = this.get_cipher(this.key, this.method, 0, decipher_iv);
                        result = this.decipher.update(buf.slice(decipher_iv_len));
                        return result;
                    } else {
                        result = this.decipher.update(buf);
                        return result;
                    }
                } else {
                    return substitute(this.decryptTable, buf);
                }
            };

            return Encryptor;

        })();

        return {
            getTable: getTable,
            Encryptor: Encryptor
        };
    };

    function merge_sortLib() {

        var merge, merge_sort;

        merge = function (left, right, comparison) {
            var result;
            result = new Array();
            while ((left.length > 0) && (right.length > 0)) {
                if (comparison(left[0], right[0]) <= 0) {
                    result.push(left.shift());
                } else {
                    result.push(right.shift());
                }
            }
            while (left.length > 0) {
                result.push(left.shift());
            }
            while (right.length > 0) {
                result.push(right.shift());
            }
            return result;
        };

        merge_sort = function (array, comparison) {
            var middle;
            if (array.length < 2) {
                return array;
            }
            middle = Math.ceil(array.length / 2);
            return merge(merge_sort(array.slice(0, middle), comparison), merge_sort(array.slice(middle), comparison), comparison);
        };

        return {
            merge_sort: merge_sort
        };
    };

    w.Server = (function () {
        WebSocketServer = WebSocket.Server;


        var Encryptor = encryptLib().Encryptor;
        var inetNtoa = function (buf) {
            return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
        };

        function serverClass(port, key, method, timeout) {
            if (typeof port == 'undefined' || typeof key == 'undefined') {
                throw new Error('MissingRequireParamaters');
            }

            var config = {
                server: "www.example.com",
                local_address: "0.0.0.0",
                scheme: "ws",
                local_port: port,
                remote_port: 80,
                password: key,
                timeout: timeout || 600,
                method: method || 'aes-256-cfb'
            }


            this.timeout = Math.floor(config.timeout * 1000);
            this.PORT = config.remote_port;
            this.LOCAL_ADDRESS = config.local_address;
            this.KEY = config.password;
            this.METHOD = config.method;

            this.server = null;
            this.wss = null;
        }


        serverClass.prototype.createServer = function (welcomMessage) {
            welcomMessage = welcomMessage || '<!DOCTYPE html><html><head><meta charset="utf-8"><title>歡迎使用daonodess</title><style>body {text-align:center;}</style></head><body><div><h1>DaoNodeSS</h1><p>看到此頁面代表程序正確運行</p><p>本程式改自shadowsocks-heroku，目的是把這個專案Docker化</p><p>並支援自己設定參數</p><p>原GitHub帳戶搞丟了，目前repo放在我的主帳</p></div></body></html>';


            this.server = http.createServer(function (req, res) {
                res.writeHead(200, {
                    'Content-Type': 'text/html'
                });

                return res.end(welcomMessage);
            });

            this.server.listen(this.PORT, this.LOCAL_ADDRESS, function () {
                var address;
                address = this.server.address();
                return console.log("server listening at", address);
            }.bind(this));

            this.server.on("error", function (e) {
                if (e.code === "EADDRINUSE") {
                    console.log("address in use, aborting");
                }
                return process.exit(1);
            });
        }

        serverClass.prototype.createSocket = function () {
            if (this.server === null) {
                throw new Error('HTTPServerNotInitialized')
            }

            this.wss = new WebSocketServer({
                server: this.server
            });

            this.wss.on("connection", function (ws) {
                var addrLen, cachedPieces, encryptor, headerLength, remote, remoteAddr, remotePort, stage;
                console.log("server connected");
                console.log("concurrent connections:", wss.clients.length);
                encryptor = new Encryptor(KEY, METHOD);
                stage = 0;
                headerLength = 0;
                remote = null;
                cachedPieces = [];
                addrLen = 0;
                remoteAddr = null;
                remotePort = null;
                ws.on("message", function (data, flags) {
                    var addrtype, buf, e, error;
                    data = encryptor.decrypt(data);
                    if (stage === 5) {
                        if (!remote.write(data)) {
                            ws._socket.pause();
                        }
                        return;
                    }
                    if (stage === 0) {
                        try {
                            addrtype = data[0];
                            if (addrtype === 3) {
                                addrLen = data[1];
                            } else if (addrtype !== 1) {
                                console.warn("unsupported addrtype: " + addrtype);
                                ws.close();
                                return;
                            }
                            if (addrtype === 1) {
                                remoteAddr = inetNtoa(data.slice(1, 5));
                                remotePort = data.readUInt16BE(5);
                                headerLength = 7;
                            } else {
                                remoteAddr = data.slice(2, 2 + addrLen).toString("binary");
                                remotePort = data.readUInt16BE(2 + addrLen);
                                headerLength = 2 + addrLen + 2;
                            }
                            remote = net.connect(remotePort, remoteAddr, function () {
                                var i, piece;
                                console.log("connecting", remoteAddr);
                                i = 0;
                                while (i < cachedPieces.length) {
                                    piece = cachedPieces[i];
                                    remote.write(piece);
                                    i++;
                                }
                                cachedPieces = null;
                                return stage = 5;
                            });
                            remote.on("data", function (data) {
                                data = encryptor.encrypt(data);
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(data, {
                                        binary: true
                                    });
                                    if (ws.bufferedAmount > 0) {
                                        remote.pause();
                                    }
                                }
                            });
                            remote.on("end", function () {
                                ws.close();
                                return console.log("remote disconnected");
                            });
                            remote.on("drain", function () {
                                return ws._socket.resume();
                            });
                            remote.on("error", function (e) {
                                ws.terminate();
                                return console.log("remote: " + e);
                            });
                            remote.setTimeout(timeout, function () {
                                console.log("remote timeout");
                                remote.destroy();
                                return ws.close();
                            });
                            if (data.length > headerLength) {
                                buf = new Buffer(data.length - headerLength);
                                data.copy(buf, 0, headerLength);
                                cachedPieces.push(buf);
                                buf = null;
                            }
                            return stage = 4;
                        } catch (error) {
                            e = error;
                            console.warn(e);
                            if (remote) {
                                remote.destroy();
                            }
                            return ws.close();
                        }
                    } else {
                        if (stage === 4) {
                            return cachedPieces.push(data);
                        }
                    }
                });
                ws.on("ping", function () {
                    return ws.pong('', null, true);
                });
                ws._socket.on("drain", function () {
                    if (stage === 5) {
                        return remote.resume();
                    }
                });
                ws.on("close", function () {
                    console.log("server disconnected");
                    console.log("concurrent connections:", wss.clients.length);
                    if (remote) {
                        return remote.destroy();
                    }
                });
                return ws.on("error", function (e) {
                    console.warn("server: " + e);
                    console.log("concurrent connections:", wss.clients.length);
                    if (remote) {
                        return remote.destroy();
                    }
                });
            });
        };

        return serverClass;
    })();
})(global.Server || global);