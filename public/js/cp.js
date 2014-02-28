var coinpunk = {};

$.ajax("../config.json", {
    async: !1,
    complete: function(resp) {
        coinpunk.config = resp.responseJSON;
    }
}), coinpunk.utils = {}, coinpunk.utils.stripTags = function(html) {
    return String(html).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}, coinpunk.Template = {
    preCache: [ "accounts/import", "accounts/settings", "addresses/list", "addresses/request", "dashboard/received", "dashboard/sent", "tx/details", "tx/send", "backup", "dashboard", "header", "node_error", "signin", "signup", "buy" ],
    templateCache: {},
    get: function(path, callback) {
        var self = this;
        $.get("views/" + path + ".html", function(res) {
            self.templateCache[path] = res, callback && callback(res);
        });
    },
    draw: function(id, path, data, callback) {
        var self = this;
        this.templateCache[path] ? this.parseTemplate(id, this.templateCache[path], data, callback) : this.get(path, function(res) {
            self.parseTemplate(id, res, data, callback);
        });
    },
    parseTemplate: function(id, template, data, callback) {
        $("#" + id).html(_.template(template, data, {
            variable: "data"
        })), callback && callback(id);
    },
    loadPreCache: function() {
        for (var i = 0; i < this.preCache.length; i++) this.get(this.preCache[i]);
    }
}, coinpunk.Template.loadPreCache(), coinpunk.Database = function() {
    this.coinpunkCurrencyName = "coinpunkCurrency", this.storage = localStorage;
}, coinpunk.Database.prototype.setCurrency = function(currency) {
    return localStorage.setItem(this.coinpunkCurrencyName, currency);
}, coinpunk.Database.prototype.getCurrency = function() {
    return localStorage.getItem(this.coinpunkCurrencyName);
}, coinpunk.Database.prototype.setSuccessMessage = function(message) {
    return localStorage.setItem("successMessage", message);
}, coinpunk.Database.prototype.getSuccessMessage = function() {
    var msg = localStorage.getItem("successMessage");
    return localStorage.removeItem("successMessage"), msg;
}, coinpunk.database = new coinpunk.Database(), coinpunk.Wallet = function(walletKey, walletId) {
    this.network = coinpunk.config.network || "prod", this.walletKey = walletKey, this.walletId = walletId, 
    this.defaultIterations = 1e3, this.serverKey = void 0, this.transactions = [], this.unspent = [], 
    this.minimumConfirmations = 1, this.unspentConfirmations = [], this.networkObj = "testnet" === this.network ? bitcore.networks.testnet : bitcore.networks.livenet;
    var keyPairs = [];
    this.loadPayloadWithLogin = function(id, password, payload) {
        return this.createWalletKey(id, password), this.loadPayload(payload), !0;
    }, this.loadPayload = function(encryptedJSON) {
        var payloadJSON = sjcl.decrypt(this.walletKey, encryptedJSON);
        this.payloadHash = this.computePayloadHash(payloadJSON);
        var payload = JSON.parse(payloadJSON);
        return keyPairs = payload.keyPairs, this.transactions = payload.transactions || [], 
        this.unspent = payload.unspent || [], !0;
    }, this.mergePayload = function(wallet) {
        var payloadJSON = sjcl.decrypt(this.walletKey, wallet), payload = JSON.parse(payloadJSON);
        return keyPairs = _.uniq(_.union(payload.keyPairs, keyPairs), !1, function(item) {
            return item.key;
        }), this.transactions = _.uniq(_.union(payload.transactions, this.transactions), !1, function(item) {
            return item.hash;
        }), this.unspent = _.uniq(_.union(payload.unspent, this.unspent), !1, function(item) {
            return item.hash;
        }), this.payloadHash = this.computePayloadHash(payloadJSON), !0;
    }, this.createNewAddress = function(name, isChange) {
        var Walletkey = bitcore.WalletKey.class(), wKey = new Walletkey({
            network: this.networkObj
        });
        wKey.generate();
        var obj = wKey.storeObj(), newKeyPair = {
            key: obj.priv,
            publicKey: obj.pub,
            address: obj.addr,
            isChange: 1 == isChange
        };
        return name && (newKeyPair.name = name), keyPairs.push(newKeyPair), newKeyPair.address;
    }, this.removeAddress = function(address) {
        var i = 0;
        for (i = 0; i < keyPairs.length; i++) keyPairs[i].address == address && keyPairs.splice(i, 1);
    }, this.getAddressName = function(address) {
        for (var i = 0; i < keyPairs.length; i++) if (keyPairs[i].address == address) return keyPairs[i].name;
    }, this.addresses = function() {
        for (var addrs = [], i = 0; i < keyPairs.length; i++) addrs.push({
            address: keyPairs[i].address,
            name: keyPairs[i].name,
            isChange: keyPairs[i].isChange
        });
        return addrs;
    }, this.receiveAddresses = function() {
        for (var addrs = [], i = 0; i < keyPairs.length; i++) 1 != keyPairs[i].isChange && addrs.push({
            address: keyPairs[i].address,
            name: keyPairs[i].name
        });
        return addrs;
    }, this.receiveAddressHashes = function() {
        for (var addrHashes = [], i = 0; i < keyPairs.length; i++) 1 != keyPairs[i].isChange && addrHashes.push(keyPairs[i].address);
        return addrHashes;
    }, this.changeAddressHashes = function() {
        for (var addrHashes = [], i = 0; i < keyPairs.length; i++) 1 == keyPairs[i].isChange && addrHashes.push(keyPairs[i].address);
        return addrHashes;
    }, this.addressHashes = function() {
        for (var addresses = this.addresses(), addressHashes = [], i = 0; i < addresses.length; i++) addressHashes.push(addresses[i].address);
        return addressHashes;
    }, this.createServerKey = function() {
        return this.serverKey = sjcl.codec.base64.fromBits(sjcl.misc.pbkdf2(this.walletKey, this.walletId, this.defaultIterations)), 
        this.serverKey;
    }, this.createWalletKey = function(id, password) {
        return this.walletKey = sjcl.codec.base64.fromBits(sjcl.misc.pbkdf2(password, id, this.defaultIterations)), 
        this.walletId = id, this.createServerKey(), this.walletKey;
    }, this.computePayloadHash = function(payloadJSON) {
        return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(payloadJSON));
    }, this.encryptPayload = function() {
        var payload = {
            keyPairs: keyPairs,
            transactions: this.transactions,
            unspent: this.unspent
        }, payloadJSON = JSON.stringify(payload);
        return this.newPayloadHash = this.computePayloadHash(payloadJSON), sjcl.encrypt(this.walletKey, payloadJSON);
    }, this.mergeUnspent = function(newUnspent) {
        var changed = !1;
        this.unspentConfirmations = this.unspentConfirmations || {};
        for (var i = 0; i < newUnspent.length; i++) {
            for (var match = !1, j = 0; j < this.unspent.length; j++) this.unspent[j].hash == newUnspent[i].hash && (match = !0);
            if (this.unspentConfirmations[newUnspent[i].hash] = newUnspent[i].confirmations, 
            1 != match) {
                changed = !0, this.unspent.push({
                    hash: newUnspent[i].hash,
                    vout: newUnspent[i].vout,
                    address: newUnspent[i].address,
                    scriptPubKey: newUnspent[i].scriptPubKey,
                    amount: newUnspent[i].amount
                });
                for (var txMatch = !1, k = 0; k < this.transactions.length; k++) this.transactions[k].hash == newUnspent[i].hash && (txMatch = !0);
                0 == txMatch && this.transactions.push({
                    hash: newUnspent[i].hash,
                    type: "receive",
                    address: newUnspent[i].address,
                    amount: newUnspent[i].amount,
                    time: new Date().getTime()
                });
            }
        }
        return changed;
    }, this.getUnspent = function(confirmations) {
        for (var confirmations = confirmations || 0, unspent = [], i = 0; i < this.unspent.length; i++) this.unspentConfirmations[this.unspent[i].hash] >= confirmations && unspent.push(this.unspent[i]);
        return unspent;
    }, this.pendingUnspentBalance = function() {
        for (var unspent = this.getUnspent(0), changeAddresses = this.changeAddressHashes(), balance = new BigNumber(0), u = 0; u < unspent.length; u++) 0 == this.unspentConfirmations[unspent[u].hash] && 0 == _.contains(changeAddresses, unspent[u].address) && (balance = balance.plus(unspent[u].amount));
        return balance;
    }, this.safeUnspentBalance = function() {
        for (var safeUnspent = this.safeUnspent(), amount = new BigNumber(0), i = 0; i < safeUnspent.length; i++) amount = amount.plus(safeUnspent[i].amount);
        return amount;
    }, this.safeUnspent = function() {
        for (var unspent = this.getUnspent(), changeAddresses = this.changeAddressHashes(), safeUnspent = [], u = 0; u < unspent.length; u++) (1 == _.contains(changeAddresses, unspent[u].address) || this.unspentConfirmations[unspent[u].hash] >= this.minimumConfirmations) && safeUnspent.push(unspent[u]);
        return safeUnspent;
    }, this.receivedAmountTotal = function() {
        for (var addresses = this.addresses(), amount = new BigNumber(0), a = 0; a < addresses.length; a++) amount = amount.plus(this.addressReceivedAmount(addresses[a]));
        return amount;
    }, this.addressReceivedAmount = function(address) {
        for (var amount = new BigNumber(0), t = 0; t < this.transactions.length; t++) this.transactions[t].address == address && (amount = amount.plus(this.transactions[t].amount));
        return amount;
    }, this.createTx = function(amtString, feeString, addressString, changeAddress) {
        var amt = Bitcoin.util.parseValue(amtString);
        if (amt == Bitcoin.BigInteger.ZERO) throw "spend amount must be greater than zero";
        if (!changeAddress) throw "change address was not provided";
        var i, fee = Bitcoin.util.parseValue(feeString || "0"), total = Bitcoin.BigInteger.ZERO.add(amt).add(fee), address = new Bitcoin.Address(addressString, this.network), sendTx = new Bitcoin.Transaction(), unspent = [], unspentAmt = Bitcoin.BigInteger.ZERO, safeUnspent = this.safeUnspent();
        for (i = 0; i < safeUnspent.length; i++) {
            unspent.push(safeUnspent[i]);
            var amountSatoshiString = new BigNumber(safeUnspent[i].amount).times(Math.pow(10, 8)).toString();
            if (unspentAmt = unspentAmt.add(new Bitcoin.BigInteger(amountSatoshiString)), unspentAmt.compareTo(total) > -1) break;
        }
        if (unspentAmt.compareTo(total) < 0) throw "you do not have enough bitcoins to send this amount";
        for (i = 0; i < unspent.length; i++) sendTx.addInput({
            hash: unspent[i].hash
        }, unspent[i].vout);
        sendTx.addOutput(address, amt);
        var remainder = unspentAmt.subtract(total);
        remainder.equals(Bitcoin.BigInteger.ZERO) || sendTx.addOutput(changeAddress, remainder);
        var hashType = 1;
        for (i = 0; i < unspent.length; i++) for (var unspentOutScript = new Bitcoin.Script(Bitcoin.convert.hexToBytes(unspent[i].scriptPubKey)), hash = sendTx.hashTransactionForSignature(unspentOutScript, i, hashType), pubKeyHash = unspentOutScript.simpleOutHash(), pubKeyHashHex = Bitcoin.convert.bytesToHex(pubKeyHash), j = 0; j < keyPairs.length; j++) if (_.isEqual(keyPairs[j].publicKey, pubKeyHashHex)) {
            var key = new Bitcoin.Key(keyPairs[j].key), signature = key.sign(hash);
            signature.push(parseInt(hashType, 10)), sendTx.ins[i].script = Bitcoin.Script.createInputScript(signature, key.getPub());
            break;
        }
        return {
            unspentsUsed: unspent,
            obj: sendTx,
            raw: Bitcoin.convert.bytesToHex(sendTx.serialize())
        };
    }, this.calculateFee = function(amtString, addressString, changeAddress) {
        var tx = this.createTx(amtString, 0, addressString, changeAddress), txSize = tx.raw.length / 2;
        return 1e-4 * Math.ceil(txSize / 1e3);
    }, this.createSend = function(amtString, feeString, addressString, changeAddress) {
        var tx = this.createTx(amtString, feeString, addressString, changeAddress);
        this.transactions.push({
            hash: Bitcoin.convert.bytesToHex(tx.obj.getHash()),
            type: "send",
            address: addressString,
            amount: amtString,
            fee: feeString,
            time: new Date().getTime()
        });
        for (var i = 0; i < tx.unspentsUsed.length; i++) this.unspent = _.reject(this.unspentsUsed, function(u) {
            return u.hash == tx.unspentsUsed[i].hash;
        });
        return tx.raw;
    }, walletKey && walletId && this.createServerKey();
}, coinpunk.Controller = function() {}, coinpunk.Controller.prototype.getUnspent = function(confirmations, callback) {
    var self = this, query = {
        addresses: coinpunk.wallet.addressHashes()
    };
    "function" == typeof confirmations ? callback = confirmations : query.confirmations = confirmations, 
    $.post("/api/tx/unspent", query, function(resp) {
        return resp.error ? (coinpunk.router.route("insight_error"), void 0) : (self.mergeUnspent(resp.unspent, callback), 
        void 0);
    });
}, coinpunk.Controller.prototype.mergeUnspent = function(unspent, callback) {
    1 == coinpunk.wallet.mergeUnspent(unspent) ? this.saveWallet({
        override: !0
    }, callback) : callback();
}, coinpunk.Controller.prototype.saveWallet = function(data, callback) {
    var self = this, data = data || {};
    data.serverKey = coinpunk.wallet.serverKey, coinpunk.wallet.sessionKey && (data.sessionKey = coinpunk.wallet.sessionKey), 
    data.payload || (data.payload = {}), data.payload.wallet || (data.payload.wallet = coinpunk.wallet.encryptPayload()), 
    data.payload.originalPayloadHash = coinpunk.wallet.payloadHash, data.payload.newPayloadHash = coinpunk.wallet.newPayloadHash, 
    $.ajax({
        type: "POST",
        url: "/api/wallet",
        data: data,
        dataType: "json",
        success: function(response) {
            return "outOfSync" == response.result ? (coinpunk.wallet.mergePayload(response.wallet), 
            self.saveWallet({
                override: !0
            }, callback)) : (coinpunk.wallet.payloadHash = coinpunk.wallet.newPayloadHash, callback && callback(response), 
            void 0);
        }
    });
}, coinpunk.Controller.prototype.deleteWallet = function(serverKey, callback) {
    $.ajax({
        type: "POST",
        url: "/api/wallet/delete",
        data: {
            serverKey: serverKey
        },
        dataType: "json",
        success: function(response) {
            callback && callback(response);
        }
    });
}, coinpunk.Controller.prototype.render = function(path, data, callback) {
    this.template("header", "header"), this.template("view", path, data, callback);
}, coinpunk.Controller.prototype.template = function(id, path, data, callback) {
    coinpunk.Template.draw(id, path, data, callback);
}, coinpunk.Controller.prototype.friendlyTimeString = function(timestamp) {
    var date = new Date(timestamp);
    return date.toLocaleString();
}, coinpunk.Controller.prototype.updateExchangeRates = function(id) {
    coinpunk.pricing.getLatest(function(price, currency) {
        $("#balanceExchange").text(" ≈ " + parseFloat(price * $("#balance").text()).toFixed(2) + " " + currency), 
        $("#exchangePrice").text("1 BTC ≈ " + price + " " + currency), $("#" + id + " .exchangePrice").remove();
        for (var prices = $("#" + id + " .addExchangePrice"), i = 0; i < prices.length; i++) $(prices[i]).append('<span class="exchangePrice"><small>' + ($(prices[i]).text().trim().split(" ")[0] * price).toFixed(2) + " " + currency + "</small></span>");
    });
}, coinpunk.Controller.prototype.minimumSendConfirmations = 1, coinpunk.Controller.prototype.minimumStrongSendConfirmations = 6, 
coinpunk.controllers = {}, coinpunk.controllers.Accounts = function() {}, coinpunk.controllers.Accounts.prototype = new coinpunk.Controller(), 
coinpunk.controllers.Accounts.prototype.requiredPasswordLength = 10, coinpunk.controllers.Accounts.prototype.passwordStrength = {
    enabled: !1,
    enable: function() {
        this.enabled !== !0 && (this.enabled = !0, $.strength("#email", "#password", function(username, password, strength) {
            $("#progressBar").css("width", strength.score + "%");
            var status = strength.status.charAt(0).toUpperCase() + strength.status.slice(1);
            $("#passwordStrengthStatus").text(status);
        }));
    }
}, coinpunk.controllers.Accounts.prototype.signin = function() {
    var id = $("#walletId").val(), password = $("#password").val(), errorDiv = $("#errors");
    errorDiv.addClass("hidden"), errorDiv.html("");
    var wallet = new coinpunk.Wallet(), body = (wallet.createWalletKey(id, password), 
    wallet.encryptPayload(), {
        serverKey: wallet.serverKey
    }), authCode = $("#authCode");
    authCode && (body.authCode = authCode.val()), $.get("/api/wallet", body, function(response) {
        "error" == response.result ? (errorDiv.removeClass("hidden"), errorDiv.text(response.message)) : "authCodeNeeded" == response.result ? (errorDiv.removeClass("hidden"), 
        errorDiv.text(response.message), $("#signinPassword").after('\n        <div class="form-group">\n          <label for="authCode" class="col-lg-2 control-label">Auth Code</label>\n          <div class="col-lg-4">\n            <input id="authCode" type="password" class="form-control" placeholder="">\n          </div>\n        </div>\n      '), 
        $("#authCode").focus(), coinpunk.usingAuthKey = !0) : (errorDiv.addClass("hidden"), 
        wallet.loadPayload(response.wallet), wallet.sessionKey = response.sessionKey, coinpunk.wallet = wallet, 
        coinpunk.router.listener(), coinpunk.router.route("dashboard"));
    });
}, coinpunk.controllers.Accounts.prototype.disableSubmitButton = function() {
    var button = $("#createAccountButton");
    button.attr("disabled", "disabled"), button.removeClass("btn-success"), button.text("Creating account, please wait..");
}, coinpunk.controllers.Accounts.prototype.enableSubmitButton = function() {
    var button = $("#createAccountButton");
    button.removeAttr("disabled"), button.addClass("btn-success"), button.html('<i class="fa fa-user"></i> Create Account');
}, coinpunk.controllers.Accounts.prototype.create = function() {
    var self = this, email = $("#email").val(), password = $("#password").val(), passwordConfirm = $("#password_confirm").val(), errors = [];
    null === /.+@.+\..+/.exec(email) && errors.push("Email is not valid."), "" === password && errors.push("Password cannot be blank."), 
    password != passwordConfirm && errors.push("Passwords do not match."), password.length < this.requiredPasswordLength && errors.push("Password must be at least 10 characters.");
    var errorsDiv = $("#errors");
    if (errors.length > 0) {
        errorsDiv.html("");
        for (var i = 0; i < errors.length; i++) errorsDiv.html(errorsDiv.html() + coinpunk.utils.stripTags(errors[i]) + "<br>");
        $("#errors").removeClass("hidden");
    } else {
        $("#errors").addClass("hidden"), this.disableSubmitButton();
        {
            var wallet = new coinpunk.Wallet(), address = wallet.createNewAddress("Default");
            wallet.createWalletKey(email, password);
        }
        coinpunk.wallet = wallet, this.saveWallet({
            address: address,
            payload: {
                email: email
            }
        }, function(response) {
            if ("ok" == response.result) coinpunk.wallet.sessionKey = response.sessionKey, coinpunk.router.listener(), 
            coinpunk.router.route("dashboard"); else if ("exists" == response.result) delete coinpunk.wallet, 
            errorsDiv.html('Wallet already exists, perhaps you want to <a href="#/signin">sign in</a> instead?'), 
            errorsDiv.removeClass("hidden"), self.enableSubmitButton(); else {
                errorsDiv.html("");
                for (var i = 0; i < response.messages.length; i++) errorsDiv.html(errorsDiv.html() + coinpunk.utils.stripTags(response.messages[i]) + "<br>");
                $("#errors").removeClass("hidden"), self.enableSubmitButton();
            }
        });
    }
}, coinpunk.controllers.Accounts.prototype.performImport = function(id, password) {
    var button = $("#importButton");
    button.attr("disabled", "disabled");
    var id = $("#importId").val(), password = $("#importPassword").val(), file = $("#importFile").get(0).files[0], self = this, reader = new FileReader();
    reader.onload = function(walletText) {
        var wallet = new coinpunk.Wallet();
        try {
            wallet.loadPayloadWithLogin(id, password, walletText.target.result);
        } catch (e) {
            return $("#importErrorDialog").removeClass("hidden"), $("#importErrorMessage").text("Wallet import failed. Check the credentials and wallet file."), 
            button.removeAttr("disabled"), void 0;
        }
        if (wallet.transactions && wallet.addresses()) {
            {
                wallet.encryptPayload();
            }
            coinpunk.wallet = wallet, self.saveWallet({
                importAddresses: coinpunk.wallet.addressHashes()
            }, function(resp) {
                if ("exists" == resp.result) return $("#importErrorDialog").removeClass("hidden"), 
                $("#importErrorMessage").text("Cannot import your wallet, because the wallet already exists on this server."), 
                button.removeAttr("disabled"), void 0;
                var msg = "Wallet import successful! There will be a delay in viewing your transactions until the server finishes scanning for unspent transactions on your addresses. Please be patient.";
                coinpunk.database.setSuccessMessage(msg), coinpunk.router.route("dashboard");
            });
        } else $("#importErrorDialog").removeClass("hidden"), $("#importErrorMessage").text("Not a valid wallet backup file."), 
        button.removeAttr("disabled");
    };
    try {
        reader.readAsText(file);
    } catch (e) {
        $("#importErrorDialog").removeClass("hidden"), $("#importErrorMessage").text("You must provide a wallet backup file."), 
        button.removeAttr("disabled");
    }
}, coinpunk.controllers.Accounts.prototype.changeId = function() {
    var idObj = $("#changeEmailNew"), passwordObj = $("#changeEmailPassword"), id = idObj.val(), password = passwordObj.val(), self = this;
    if (null === /.+@.+\..+/.exec(id)) return self.changeDialog("danger", "Email is not valid."), 
    void 0;
    var originalWalletId = coinpunk.wallet.walletId, originalServerKey = coinpunk.wallet.serverKey, checkWallet = (coinpunk.wallet.payloadHash, 
    new coinpunk.Wallet());
    if (checkWallet.createWalletKey(originalWalletId, password), checkWallet.serverKey != coinpunk.wallet.serverKey) return self.changeDialog("danger", "The provided password does not match. Please try again."), 
    void 0;
    coinpunk.wallet.createWalletKey(id, password);
    var payload = {
        originalServerKey: originalServerKey,
        wallet: coinpunk.wallet.encryptPayload(),
        serverKey: coinpunk.wallet.serverKey,
        email: id,
        payloadHash: coinpunk.wallet.payloadHash
    };
    coinpunk.wallet.sessionKey && (payload.sessionKey = coinpunk.wallet.sessionKey), 
    $.post("api/change", payload, function(response) {
        return "ok" != response.result ? self.changeDialog("danger", "An unknown error has occured, please try again later.") : (self.template("header", "header"), 
        idObj.val(""), passwordObj.val(""), self.changeDialog("success", "Successfully changed email. You will need to use this to login next time, don't forget it!"), 
        void 0);
    });
}, coinpunk.controllers.Accounts.prototype.changePassword = function() {
    var self = this, currentPasswordObj = $("#currentPassword"), newPasswordObj = $("#newPassword"), confirmNewPasswordObj = $("#confirmNewPassword"), currentPassword = currentPasswordObj.val(), newPassword = newPasswordObj.val(), confirmNewPassword = confirmNewPasswordObj.val();
    if (newPassword != confirmNewPassword) return this.changeDialog("danger", "New passwords do not match."), 
    void 0;
    if (newPassword < this.requiredPasswordLength) return this.changeDialog("danger", "Password must be at least " + this.requiredPasswordLength + " characters."), 
    void 0;
    var checkWallet = new coinpunk.Wallet();
    if (checkWallet.createWalletKey(coinpunk.wallet.walletId, currentPassword), checkWallet.serverKey != coinpunk.wallet.serverKey) return currentPasswordObj.val(""), 
    this.changeDialog("danger", "Current password is not valid, please re-enter."), 
    void 0;
    var originalServerKey = coinpunk.wallet.serverKey;
    coinpunk.wallet.createWalletKey(coinpunk.wallet.walletId, newPassword);
    var payload = {
        originalServerKey: originalServerKey,
        wallet: coinpunk.wallet.encryptPayload(),
        serverKey: coinpunk.wallet.serverKey,
        payloadHash: coinpunk.wallet.payloadHash
    };
    coinpunk.wallet.sessionKey && (payload.sessionKey = coinpunk.wallet.sessionKey), 
    $.post("api/change", payload, function(response) {
        return "error" == response.result ? (self.changeDialog("danger", "Error changing password"), 
        coinpunk.wallet.createWalletKey(coinpunk.wallet.walletId, currentPassword), void 0) : (self.template("header", "header"), 
        currentPasswordObj.val(""), newPasswordObj.val(""), confirmNewPasswordObj.val(""), 
        self.changeDialog("success", "Successfully changed password. You will need to use this to login next time, don't forget it!"), 
        void 0);
    });
}, coinpunk.controllers.Accounts.prototype.changeDialog = function(type, message) {
    $("#changeDialog").removeClass("alert-danger"), $("#changeDialog").removeClass("alert-success"), 
    $("#changeDialog").addClass("alert-" + type), $("#changeDialog").removeClass("hidden"), 
    $("#changeMessage").text(message);
}, $("body").on("click", "#generateAuthQR", function() {
    var e = $("#generateAuthQR");
    e.addClass("hidden"), $.get("api/generateAuthKey", function(resp) {
        e.after('<div id="authQR"></div>');
        var authURI = new URI({
            protocol: "otpauth",
            hostname: "totp",
            path: "Coinpunk:" + coinpunk.wallet.walletId
        });
        authURI.setSearch({
            issuer: "Coinpunk",
            secret: resp.key
        }), new QRCode(document.getElementById("authQR"), authURI.toString()), $("#authQR").after('\n      <form role="form" id="submitAuth">\n        <p>Enter code shown on Google Authenticator:</p>\n        <input type="hidden" id="authKeyValue" value="' + resp.key + '">\n        <div class="form-group">\n          <label for="confirmAuthCode">Confirm Auth Code</label>\n          <input class="form-control" type="text" id="confirmAuthCode" autocorrect="off" autocomplete="off">\n        </div>\n        <button type="submit" class="btn btn-primary">Confirm</button>\n      </form>\n    '), 
        $("#confirmAuthCode").focus();
    });
}), $("body").on("submit", "#submitAuth", function() {
    var e = $("#submitAuth #confirmAuthCode");
    $.post("api/setAuthKey", {
        serverKey: coinpunk.wallet.serverKey,
        sessionKey: coinpunk.wallet.sessionKey,
        key: $("#authKeyValue").val(),
        code: e.val()
    }, function(res) {
        1 != res.set ? $("#authKey").text("Code save failed. Please reload and try again.") : (coinpunk.usingAuthKey = !0, 
        $("#authKey").text("Successfully saved! You will now need your device to login."));
    });
}), $("body").on("submit", "#disableAuth", function() {
    var dialog = $("#disableAuthDialog");
    dialog.addClass("hidden");
    var authCode = $("#disableAuth #disableAuthCode").val();
    $.post("api/disableAuthKey", {
        serverKey: coinpunk.wallet.serverKey,
        sessionKey: coinpunk.wallet.sessionKey,
        authCode: authCode
    }, function(resp) {
        return "error" == resp.result ? (dialog.text(resp.message), dialog.removeClass("hidden"), 
        void 0) : (coinpunk.usingAuthKey = !1, coinpunk.database.setSuccessMessage("Two factor authentication has been disabled."), 
        coinpunk.router.route("dashboard", "settings"), void 0);
    });
}), coinpunk.controllers.accounts = new coinpunk.controllers.Accounts(), coinpunk.controllers.Addresses = function() {}, 
coinpunk.controllers.Addresses.prototype = new coinpunk.Controller(), coinpunk.controllers.Addresses.prototype.list = function() {
    var self = this;
    this.render("addresses/list", {
        addresses: coinpunk.wallet.receiveAddresses()
    }, function(id) {
        self.updateExchangeRates(id);
    });
}, coinpunk.controllers.Addresses.prototype.generateNewAddress = function(label) {
    var self = this, label = label || "", address = coinpunk.wallet.createNewAddress(label, !1);
    this.saveWallet({
        address: address,
        override: !0
    }, function(response) {
        if ("ok" != response.result) return coinpunk.wallet.removeAddress(address), $("#newAddressDialog").removeClass("hidden"), 
        $("#newAddressMessage").text("There was an error creating your address, do not use the new address. Try logging back in, or please try again later."), 
        void 0;
        self.render("addresses/list", {
            addresses: coinpunk.wallet.addresses()
        }, function(id) {
            self.updateExchangeRates(id, !1);
        }), $("#newAddressDialog").removeClass("hidden");
        var message = "Created new address " + address;
        if ("" != label) var message = message + " with label " + label;
        $("#newAddressMessage").text(message + ".");
    });
}, coinpunk.controllers.Addresses.prototype.request = function(address) {
    var self = this;
    this.render("addresses/request", {
        address: address
    }, function() {
        self.drawRequestQR(address);
    });
}, coinpunk.controllers.Addresses.prototype.requestExchangeUpdate = function() {
    var amount = $("#amount").val();
    coinpunk.pricing.getLatest(function(price) {
        var newAmount = parseFloat(price * amount).toFixed(2);
        "NaN" != newAmount && $("#amountExchange").val(newAmount);
    });
}, coinpunk.controllers.Addresses.prototype.requestBTCUpdate = function() {
    var amountExchange = $("#amountExchange").val();
    coinpunk.pricing.getLatest(function(price) {
        if (0 != amountExchange) {
            var newAmount = parseFloat(amountExchange / price).toFixed(6).replace(/0+$/, "");
            "NaN" != newAmount && $("#amount").val(newAmount);
        }
    });
}, coinpunk.controllers.Addresses.prototype.drawRequestQR = function(address) {
    var uri = URI({
        protocol: "bitcoin",
        path: address
    }), amount = $("#amount").val(), label = $("#label").val(), message = $("#message").val();
    amount && "" != amount && "0.00" != amount && uri.addQuery("amount", amount), label && "" != label && uri.addQuery("label", label), 
    message && "" != message && uri.addQuery("message", message), $("#qrcode").html(""), 
    new QRCode(document.getElementById("qrcode"), uri.toString().replace("://", ":"));
}, coinpunk.controllers.addresses = new coinpunk.controllers.Addresses(), coinpunk.controllers.Dashboard = function() {}, 
coinpunk.controllers.Dashboard.prototype = new coinpunk.Controller(), coinpunk.controllers.Dashboard.prototype.renderDashboard = function() {
    var i = 0, self = this;
    $("#balance").text(coinpunk.wallet.safeUnspentBalance()), $("#pendingBalance").text(coinpunk.wallet.pendingUnspentBalance());
    var txHashes = [], txs = coinpunk.wallet.transactions;
    for (i = 0; i < txs.length; i++) txHashes.push(txs[i].hash);
    $.post("/api/tx/details", {
        txHashes: txHashes
    }, function(resp) {
        for (i = 0; i < txs.length; i++) for (var j = 0; j < resp.length; j++) txs[i].hash == resp[j].hash && (txs[i].confirmations = resp[j].confirmations);
        var stxs = [];
        for (i = 0; i < txs.length; i++) "send" == txs[i].type && stxs.push(txs[i]);
        var rtxs = [];
        for (i = 0; i < txs.length; i++) "receive" == txs[i].type && rtxs.push(txs[i]);
        self.template("sentTransactions", "dashboard/sent", {
            tx: stxs.reverse()
        }, function(id) {
            $("#" + id + " [rel='tooltip']").tooltip(), self.updateExchangeRates(id);
        }), self.template("receivedTransactions", "dashboard/received", {
            category: "Received",
            tx: rtxs.reverse()
        }, function(id) {
            self.updateExchangeRates("receivedTransactions"), $("#" + id + " [rel='tooltip']").tooltip();
        });
    });
}, coinpunk.controllers.Dashboard.prototype.index = function() {
    var self = this;
    this.render("dashboard", {}, function() {
        self.firstDashboardLoad ? self.renderDashboard() : (self.firstDashboardLoad = !0, 
        self.getUnspent(function() {
            self.renderDashboard();
        }));
    });
}, coinpunk.controllers.Dashboard.prototype.updateExchangeRates = function(id) {
    coinpunk.pricing.getLatest(function(price, currency) {
        $("#balanceExchange").text(" ≈ " + parseFloat(price * $("#balance").text()).toFixed(2) + " " + currency), 
        $("#exchangePrice").text("1 BTC ≈ " + price + " " + currency), $("#" + id + " .exchangePrice").remove();
        for (var prices = $("#" + id + " .addExchangePrice"), i = 0; i < prices.length; i++) $(prices[i]).append('<span class="exchangePrice pull-right"><small>' + ($(prices[i]).text().split(" ")[0] * price).toFixed(2) + " " + currency + "</small></span>");
    });
}, coinpunk.controllers.dashboard = new coinpunk.controllers.Dashboard(), coinpunk.controllers.Tx = function() {}, 
coinpunk.controllers.Tx.prototype = new coinpunk.Controller(), coinpunk.controllers.Tx.prototype.defaultFee = "0.0001", 
coinpunk.controllers.Tx.prototype.minimumConfirmationsToSpend = 1, coinpunk.controllers.Tx.prototype.details = function(txHash) {
    var self = this;
    $.post("/api/tx/details", {
        txHashes: [ txHash ]
    }, function(resp) {
        self.render("tx/details", {
            tx: resp[0]
        }, function(id) {
            $("#" + id + " [rel='tooltip']").tooltip();
        });
    });
}, coinpunk.controllers.Tx.prototype.send = function() {
    var self = this;
    this.getUnspent(function() {
        coinpunk.router.render("view", "tx/send", {
            balance: coinpunk.wallet.safeUnspentBalance()
        }, function(id) {
            self.updateExchangeRates(id, !1), $("#" + id + " [rel='tooltip']").tooltip();
        });
    });
}, coinpunk.controllers.Tx.prototype.sendExchangeUpdate = function() {
    var self = this, amount = $("#amount").val();
    coinpunk.pricing.getLatest(function(price) {
        var newAmount = parseFloat(price * amount).toFixed(2);
        if ("NaN" != newAmount) {
            var amountExchange = $("#amountExchange");
            amountExchange.val() != newAmount && ($("#amountExchange").val(newAmount), self.calculateFee());
        }
    });
}, coinpunk.controllers.Tx.prototype.sendBTCUpdate = function() {
    var self = this, amountExchange = $("#amountExchange").val();
    coinpunk.pricing.getLatest(function(price) {
        if (0 != amountExchange) {
            var newAmount = parseFloat(amountExchange / price).toFixed(6).replace(/\.0+$/, "");
            if ("NaN" != newAmount) {
                var amount = $("#amount");
                amount.val() != newAmount && (amount.val(newAmount), self.calculateFee());
            }
        }
    });
}, coinpunk.controllers.Tx.prototype.create = function() {
    var self = this, sendButton = $("#sendButton");
    sendButton.addClass("disabled");
    var address = $("#createSendForm #address").val(), amount = $("#createSendForm #amount").val(), errors = [], errorsDiv = $("#errors");
    this.calculateFee();
    var calculatedFee = $("#calculatedFee").val();
    if (errorsDiv.addClass("hidden"), errorsDiv.html(""), "" == address) errors.push("You cannot have a blank sending address."); else try {
        new Bitcoin.Address(address, coinpunk.config.network);
    } catch (e) {
        errors.push("The provided bitcoin address is not valid.");
    }
    for (var myAddresses = coinpunk.wallet.addresses(), i = 0; i < myAddresses.length; i++) myAddresses[i].address == address && errors.push("You cannot send to your own bitcoin wallet.");
    if ("" == amount || 0 == parseFloat(amount) ? errors.push("You must have a valid amount to send.") : null === /^[0-9]+$|^[0-9]+\.[0-9]+$|^\.[0-9]+$/.exec(amount) ? errors.push("You must have a valid amount to send.") : coinpunk.wallet.safeUnspentBalance().lessThan(new BigNumber(amount).plus(calculatedFee)) && errors.push("Cannot spend more bitcoins than you currently have."), 
    errors.length > 0) return this.displayErrors(errors, errorsDiv), sendButton.removeClass("disabled"), 
    void 0;
    var changeAddress = $("#changeAddress").val();
    "" == changeAddress && (changeAddress = coinpunk.wallet.createNewAddress("change", !0));
    var rawtx = coinpunk.wallet.createSend(amount, calculatedFee, address, changeAddress);
    self.saveWallet({
        override: !0,
        address: changeAddress
    }, function(response) {
        "error" == response.result && "Invalid session key" == response.messages[0] ? (self.displayErrors([ "Fatal error: invalid session key, tx was not sent, logging out" ], errorsDiv), 
        delete coinpunk.wallet) : "ok" != response.result ? (self.displayErrors([ "An unknown error has occured, tx was not sent. Logging out. Please try again later." ], errorsDiv), 
        delete coinpunk.wallet) : $.post("/api/tx/send", {
            tx: rawtx
        }, function() {
            coinpunk.database.setSuccessMessage("Sent " + amount + " BTC to " + address + "."), 
            self.getUnspent(function() {
                coinpunk.router.route("dashboard");
            });
        });
    });
}, coinpunk.controllers.Tx.prototype.displayErrors = function(errors, errorsDiv) {
    if (errors.length > 0) {
        errorsDiv.removeClass("hidden");
        for (var i = 0; i < errors.length; i++) $("#errors").html($("#errors").html() + coinpunk.utils.stripTags(errors[i]) + "<br>");
    } else ;
}, coinpunk.controllers.Tx.prototype.calculateFee = function() {
    var address = $("#address").val(), amount = $("#amount").val(), sendAmount = $("#sendAmount");
    if (amount != sendAmount.val() && (sendAmount.val(amount), "" != address && "" != amount)) {
        var changeAddress = $("#changeAddress").val(), calculatedFee = $("#calculatedFee").val();
        "" == changeAddress && (changeAddress = coinpunk.wallet.createNewAddress("change", !0), 
        $("#changeAddress").val(changeAddress));
        var calculatedFee = coinpunk.wallet.calculateFee(amount, address, changeAddress);
        $("#calculatedFee").val(calculatedFee), $("#fee").text(coinpunk.wallet.calculateFee(amount, address, changeAddress) + " BTC"), 
        this.updateExchangeRates("container", !1);
    }
}, coinpunk.controllers.Tx.prototype.scanQR = function(event) {
    var errorsDiv = $("#errors");
    if (errorsDiv.addClass("hidden"), errorsDiv.html(""), 1 != event.target.files.length && 0 != event.target.files[0].type.indexOf("image/")) return this.displayErrors([ "You must provide only one image file." ], errorsDiv);
    qrcode.callback = function(result) {
        if ("error decoding QR Code" === result) return errorsDiv.removeClass("hidden").text("Could not process the QR code, the image may be blurry. Please try again.");
        console.log(result);
        var uri = new URI(result);
        if ("" == uri.protocol()) return $("#address").val(uri.toString()), coinpunk.controllers.tx.calculateFee(), 
        void 0;
        if ("bitcoin" != uri.protocol()) return errorsDiv.removeClass("hidden").text("Not a valid Bitcoin QR code.");
        var address = uri.path();
        if (!address || "" == address) return errorsDiv.removeClass("hidden").text("No Bitcoin address found in QR code.");
        $("#address").val(address);
        var queryHash = uri.search(!0);
        queryHash.amount && ($("#amount").val(queryHash.amount), coinpunk.controllers.tx.sendExchangeUpdate(), 
        coinpunk.controllers.tx.calculateFee());
    };
    var canvas = document.createElement("canvas"), context = canvas.getContext("2d"), img = new Image();
    img.onload = function() {
        2448 == img.width && 3264 == img.height || 3264 == img.width && 2448 == img.height ? (canvas.width = 1024, 
        canvas.height = 1365, context.drawImage(img, 0, 0, 1024, 1365)) : img.width > 1024 || img.height > 1024 ? (canvas.width = .15 * img.width, 
        canvas.height = .15 * img.height, context.drawImage(img, 0, 0, .15 * img.width, .15 * img.height)) : (canvas.width = img.width, 
        canvas.height = img.height, context.drawImage(img, 0, 0, img.width, img.height)), 
        qrcode.decode(canvas.toDataURL("image/png"));
    }, img.src = URL.createObjectURL(event.target.files[0]);
}, coinpunk.controllers.tx = new coinpunk.controllers.Tx(), coinpunk.pricing = {
    cacheTimeout: 3600,
    pricesApiUrl: "/api/weighted_prices",
    defaultCurrency: "USD",
    queuedRequests: [],
    getLatest: function(callback) {
        var self = this;
        return 1 == this.inProgress ? this.queuedRequests.push(callback) : (!self.cachedResponse || !self.cachedResponseTime || new Date().getTime() / 1e3 - self.cachedResponseTime > self.cacheTimeout ? (this.inProgress = !0, 
        $.get(this.pricesApiUrl, function(response) {
            if (!response.error) {
                for (self.cachedResponse = response, self.cachedResponseTime = new Date().getTime() / 1e3, 
                self.runCallback(callback); 0 != self.queuedRequests.length; ) self.runCallback(self.queuedRequests.pop());
                self.inProgress = !1;
            }
        })) : this.runCallback(callback), void 0);
    },
    getCurrency: function() {
        return coinpunk.database.getCurrency() || this.defaultCurrency;
    },
    runCallback: function(callback) {
        for (var currency = this.getCurrency(), i = 0; i < this.cachedResponse.length; i++) if (this.cachedResponse[i].code == this.defaultCurrency) var rate = parseFloat(this.cachedResponse[i].rate).toFixed(2);
        callback(rate, currency);
    }
}, coinpunk.router = Path, coinpunk.router.render = function(id, path, data, callback) {
    console.log("[router.js.4]", id, path, data, callback), coinpunk.Template.draw("header", "header", data, callback), 
    coinpunk.Template.draw(id, path, data, callback);
}, coinpunk.router.route = function(path) {
    window.location.href = "#/" + path;
};

var sock = null;

coinpunk.router.walletRequired = function() {
    coinpunk.wallet || coinpunk.router.route("signup");
}, coinpunk.router.listener = function() {
    sock = new SockJS("./listener");
    window.onbeforeunload = function() {
        sock && sock.close();
    }, sock.onopen = function() {
        coinpunk.router.listenerTimeout = setInterval(function() {
            sock.send(JSON.stringify({
                method: "listUnspent",
                addresses: coinpunk.wallet.addressHashes()
            }));
        }, 3e4);
    }, sock.onmessage = function(res) {
        var resData = JSON.parse(res.data);
        "listUnspent" == resData.method && coinpunk.controllers.dashboard.mergeUnspent(resData.result, function() {
            var rt = $("#receivedTransactions");
            1 == rt.length && coinpunk.controllers.dashboard.renderDashboard();
        });
    }, sock.onclose = function() {
        clearInterval(coinpunk.router.listenerTimeout), coinpunk.wallet && setTimeout("coinpunk.router.listener()", 5e3);
    };
}, coinpunk.router.initWallet = function(callback) {
    return coinpunk.wallet ? callback(!0) : (console.log("[router.js.57] = > signin"), 
    coinpunk.router.route("signin"), void 0);
}, coinpunk.router.map("#/backup").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.router.render("view", "backup");
    });
}), coinpunk.router.map("#/backup/download").to(function() {
    coinpunk.router.initWallet(function(res) {
        if (0 != res) {
            var payload = coinpunk.wallet.encryptPayload(), blob = new Blob([ payload ], {
                type: "text/plain;charset=utf-8"
            });
            saveAs(blob, "coinpunk-wallet.txt"), coinpunk.router.route("backup");
        }
    });
}), coinpunk.router.map("#/signup").to(function() {
    coinpunk.router.render("view", "signup");
}), coinpunk.router.map("#/signin").to(function() {
    return coinpunk.wallet ? coinpunk.router.render("view", "dashboard") : (console.log("[router.js.90] => render"), 
    coinpunk.router.render("view", "signin"));
}), coinpunk.router.map("#/signout").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && (coinpunk.wallet = null, clearInterval(coinpunk.router.listenerTimeout), 
        coinpunk.controllers.dashboard.firstDashboardLoad = !1, coinpunk.router.route("signin"));
    });
}), coinpunk.router.map("#/dashboard").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.controllers.dashboard.index();
    });
}), coinpunk.router.map("#/tx/details/:hash").to(function() {
    var hash = this.params.hash;
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.controllers.tx.details(hash);
    });
}), coinpunk.router.map("#/tx/send").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.controllers.tx.send();
    });
}), coinpunk.router.map("#/accounts/import").to(function() {
    coinpunk.wallet ? coinpunk.router.route("dashboard") : window.File && window.FileReader && window.FileList && window.Blob ? coinpunk.router.render("view", "accounts/import") : (alert("Importing is not supported in this browser, please upgrade."), 
    coinpunk.router.route("signin"));
}), coinpunk.router.map("#/node_error").to(function() {
    coinpunk.router.render("container", "node_error");
}), coinpunk.router.map("#/insight_error").to(function() {
    coinpunk.router.render("container", "insight_error");
}), coinpunk.router.map("#/account/settings").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.router.render("view", "accounts/settings");
    });
}), coinpunk.router.map("#/addresses/list").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.controllers.addresses.list();
    });
}), coinpunk.router.map("#/addresses/request/:address").to(function() {
    var address = this.params.address;
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.controllers.addresses.request(address);
    });
}), coinpunk.router.map("#/buy").to(function() {
    coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.router.render("view", "buy");
    });
}), coinpunk.router.map("#/").to(function() {
    console.log("[router.js.182:map:]"), coinpunk.router.initWallet(function(res) {
        0 != res && coinpunk.route("dashboard");
    });
}), coinpunk.router.root("#/"), coinpunk.router.listen();