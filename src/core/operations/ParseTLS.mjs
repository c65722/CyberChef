/**
 * @author c65722 []
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {
    cipherSuiteLookup,
    supportedGroupLookup,
    pskKeyExchangeModeLookup,
    compressionMethodLookup,
    signatureAlgorithmLookup,
    versionLookup,
    ecPointFormatLookup } from "../lib/TLSLookup.mjs";
import {fromHex, toHexFast} from "../lib/Hex.mjs";
import Stream from "../lib/Stream.mjs";
import OperationError from "../errors/OperationError.mjs";

const HandshakeType = {
    CLIENT_HELLO: 1,
    SERVER_HELLO: 2
};

/**
 *
 */
class TLSExtension {

    /**
     *
     * @param {string} type
     * @param {int} length
     * @param {any} value
     */
    constructor(type, length, value) {
        this.Type = type;
        this.Length = length;
        this.Value = value;
    }
}

/**
 *
 */
class KeyValuePair{

    /**
     *
     * @param {number} key
     * @param {string} value
     */
    constructor(key, value) {
        this.Key = "0x" + key.toString(16);
        this.Value = value;
    }
}

/**
 *
 */
class TLSExtensionsParser {

    /**
     *
     * @param {HandshakeType} type
     */
    constructor(type) {
        this._type = type;
    }

    /**
     *
     * @param {Stream} input
     */
    parse(input) {
        const length = input.readInt(2);
        const extensions = new Stream(input.getBytes(length));

        const output = {
            Length: length,
            extensions: []
        };

        while (extensions.hasMore()) {
            output.extensions.push(this._parseExtension(extensions));
        }

        return output;
    }

    /**
     *
     * @param {Stream} input
     */
    _parseExtension(input) {
        const extensionType = {
            SUPPORTED_VERSION: 43,
            SERVER_NAME: 0,
            ALPN: 16,
            KEY_SHARE: 51,
            SUPPORTED_GROUPS: 10,
            SIGNATURE_ALGORITHMS: 13,
            PSK_KEY_EXCHANGE_MODES: 45,
            PADDING: 21,
            RENEGOTIATION_INFO: 0xff01,
            EXTENDED_MASTER_SECRET: 0x0017,
            EC_POINT_FORMATS: 0x000b,
            SESSION_TICKET: 0x0023,
            STATUS_REQUEST: 0x0005,
            RECORD_SIZE_LIMIT: 0x001c,
            PRE_SHARED_KEY: 0x0029,
        };

        const key = input.readInt(2);

        switch (key) {
            case extensionType.SUPPORTED_VERSION:
                return this._parseSupportedVersions(input);
            case extensionType.SERVER_NAME:
                return this._parseServerName(input);
            case extensionType.ALPN:
                return this._parseALPN(input);
            case extensionType.KEY_SHARE:
                return this._parseKeyShare(input);
            case extensionType.SUPPORTED_GROUPS:
                return this._parseSupportedGroups(input);
            case extensionType.SIGNATURE_ALGORITHMS:
                return this._parseSignatureAlgorithms(input);
            case extensionType.PSK_KEY_EXCHANGE_MODES:
                return this._parsePSKKeyExchangeModes(input);
            case extensionType.PADDING:
                return this._parsePadding(input);
            case extensionType.RENEGOTIATION_INFO:
                return this._parseRenegotiationInfo(input);
            case extensionType.EXTENDED_MASTER_SECRET:
                return this._parseExtendedMasterSecret(input);
            case extensionType.EC_POINT_FORMATS:
                return this._parseEcPointFormats(input);
            case extensionType.SESSION_TICKET:
                return this._parseSessionTicket(input);
            case extensionType.STATUS_REQUEST:
                return this._parseStatusRequest(input);
            case extensionType.RECORD_SIZE_LIMIT:
                return this._parseRecordSizeLimit(input);
            case extensionType.PRE_SHARED_KEY:
                if (this._type === HandshakeType.CLIENT_HELLO) {
                    return this._parseClientPreSharedKey(input);
                }
                if (this._type === HandshakeType.SERVER_HELLO) {
                    return this._parseServerPreSharedKey(input);
                }
                // fall through
            default:
                return this._parseUnknown(key, input);
        }
    }

    /**
     *
     * @param {Stream} input
     */
    _parseSupportedVersions(input) {
        const extensionLength = input.readInt(2);
        if (this._type === HandshakeType.SERVER_HELLO) {
            const identifier = input.readInt(2);
            return new TLSExtension("SupportedVersions", extensionLength,
                new KeyValuePair(identifier, versionLookup(identifier)));
        }

        const output = new TLSExtension("SupportedVersions", extensionLength, []);
        const length = input.readInt(1);

        for (let i = 0; i < length; i+=2) {
            const identifier = input.readInt(2);
            output.Value.push(new KeyValuePair(identifier, versionLookup(identifier)));
        }

        return output;
    }

    /**
     *
     * @param {Stream} inputStream
     */
    _parseSupportedGroups(inputStream) {
        const extensionLength = inputStream.readInt(2);
        const output = new TLSExtension("SupporedGroups", extensionLength, []);
        const length = inputStream.readInt(2);

        for (let i = 0; i < length; i +=2) {
            const identifier = inputStream.readInt(2);
            output.Value.push(new KeyValuePair(identifier, supportedGroupLookup(identifier)));
        }

        return output;
    }

    /**
     *
     * @param {Stream} inputStream
     */
    _parsePSKKeyExchangeModes(inputStream) {
        const extensionLength = inputStream.readInt(2);
        const output = new TLSExtension("PSKKeyExchangeModes", extensionLength, []);
        const length = inputStream.readInt(1);

        for (let i = 0; i < length; i++) {
            const identifier = inputStream.readInt(1);
            output.Value.push(new KeyValuePair(identifier, pskKeyExchangeModeLookup(identifier)));
        }

        return output;
    }

    /**
     *
     * @param {Stream} input
     */
    _parseServerName(input) {
        const length = input.readInt(2);
        if (!length) {
            return new TLSExtension("ServerName", length, null);
        }
        const entryType = {
            DNS_HOSTNAME: 0
        };
        input.moveForwardsBy(2);
        const type = input.readInt(1);

        if (type !== entryType.DNS_HOSTNAME) {
            throw new OperationError("Invalid Server Name Extension");
        }
        const entryLength = input.readInt(2);
        const value = input.readString(entryLength);
        return new TLSExtension("ServerName", length, value);
    }

    /**
     *
     * @param {Stream} input
     */
    _parseKeyShare(input) {
        const extensionLength = input.readInt(2);
        const content = new Stream(input.getBytes(extensionLength));
        const length = content.readInt(2);

        const output = new TLSExtension("KeyShare", length, []);

        while (content.hasMore()) {
            const group = content.readInt(2);
            const keyExchangelength = content.readInt(2);
            const keyExchange = toHexFast(content.getBytes(keyExchangelength));

            output.Value.push({
                Group: group,
                KeyExhange: keyExchange
            });
        }
        return output;
    }

    /**
     *
     * @param {Stream} input
     */
    _parseALPN(input) {
        const extensionLength = input.readInt(2);
        const content = new Stream(input.getBytes(extensionLength));
        const length = content.readInt(2);

        const output = new TLSExtension("ALPN", length, []);

        while (content.hasMore()) {
            const stringLength = content.readInt(1);
            output.Value.push(content.readString(stringLength));
        }
        return output;
    }

    /**
     *
     * @param {Stream} input
     */
    _parseSignatureAlgorithms(input) {
        const extensionLength = input.readInt(2);
        const length = input.readInt(2);

        const output = new TLSExtension("SignatureAlgorithms", extensionLength, []);

        for (let i = 0; i < length; i+=2) {
            const identifier = input.readInt(2);
            output.Value.push(new KeyValuePair(identifier, signatureAlgorithmLookup(identifier)));
        }

        return output;
    }

    /**
     *
     * @param {Stream} input
     */
    _parsePadding(input) {
        const length = input.readInt(2);
        const padding = toHexFast(input.getBytes(length));
        return new TLSExtension("Padding", length, padding);
    }

    /**
     *
     * @param {Stream} input
     */
    _parseRenegotiationInfo(input) {
        const length = input.readInt(2);
        const renegotiationInfoLength = input.readInt(1);
        const value = renegotiationInfoLength ? "0x" + toHexFast(input.getBytes(renegotiationInfoLength)): null;
        return new TLSExtension("RenegotiationInfo", length, value);
    }

    /**
     *
     * @param {Strean} input
     */
    _parseExtendedMasterSecret(input) {
        const length = input.readInt(2);
        const value = length ? "0x" + toHexFast(input.getBytes(length)): null;
        return new TLSExtension("ExtendedMasterSecret", length, value);
    }

    /**
     *
     * @param {Stream} input
     */
    _parseEcPointFormats(input) {
        const length = input.readInt(2);
        const ecPointFormatsLength = input.readInt(1);
        const values = [];
        for (let i = 0; i < ecPointFormatsLength; i++) {
            const identifier = input.readInt(1);
            values.push(new KeyValuePair(identifier, ecPointFormatLookup(identifier)));
        }

        return new TLSExtension("ECPointFormats", length, values);
    }

    /**
     *
     * @param {Stream} input
     */
    _parseSessionTicket(input) {
        const length = input.readInt(2);
        const value = length ? "0x" + toHexFast(input.getBytes(length)): null;

        return new TLSExtension("SessionTicket", length, value);
    }

    /**
     *
     * @param {Stream} input
     */
    _parseStatusRequest(input) {
        const OCSP = 1;
        const length = input.readInt(2);
        if (!length) {
            return new TLSExtension("StatusRequest", 0, null);
        }
        const statusType = input.readInt(1);
        if (statusType === OCSP) {
            const responderIdListLength = input.readInt(2);
            const responderIdList = [];
            for (let i = 0; i < responderIdListLength; i += 2) {
                responderIdList.push("0x" + toHexFast(input.getBytes(2)));
            }

            const requestExtensionsLength = input.readInt(2);
            const requestExtensions = [];
            for (let i = 0; i < requestExtensionsLength; i += 2) {
                requestExtensions.push("0x" + toHexFast(input.getBytes(2)));
            }

            return new TLSExtension(
                "StatusRequest",
                length,
                {
                    ResponderIdList: responderIdList,
                    RequestExtensions: requestExtensions,
                });
        }

        throw new OperationError("Invalid status_request extension");
    }

    /**
     *
     * @param {number} input
     */
    _parseRecordSizeLimit(input) {
        const length = input.readInt(2);
        const value = input.readInt(2);

        return new TLSExtension("RecordSizeLimit", length, value);
    }

    /**
     *
     * @param {Stream} input
     */
    _parseClientPreSharedKey(input) {
        const length = input.readInt(2);
        const identiesLength = input.readInt(2);
        const identiesStream = new Stream(input.getBytes(identiesLength));

        const identities = [];

        while (identiesStream.hasMore()) {
            const identityLength = identiesStream.readInt(2);

            identities.push({
                Identity: "0x" + toHexFast(identiesStream.getBytes(identityLength)),
                ObfuscatedTicketAge: identiesStream.readInt(4)
            });
        }

        const pskBindersLength = input.readInt(2);
        const pskBinders = "0x" + toHexFast(input.getBytes(pskBindersLength));

        return new TLSExtension("PreSharedKey", length, {
            Identities: identities,
            pskBinders: pskBinders
        });
    }

    /**
     *
     * @param {Stream} input
     */
    _parseServerPreSharedKey(input) {
        const length = input.readInt(2);
        const value = "0x" + toHexFast(input.getBytes(2));

        return new TLSExtension("PreSharedKey", length, value);
    }

    /**
     *
     * @param key Extension key
     * @param input input stream
     */
    _parseUnknown(key, input) {
        const length = input.readInt(2);
        return {
            Type: "Unknown",
            Key: "0x" + key.toString(16),
            Length: length,
            Value: toHexFast(input.getBytes(length))
        };
    }
}

/**
 *
 */
class ClientHelloParser {

    /**
     * @param {TLSExtensionsParser} extParser
     */
    constructor(extParser) {
        this._extParser = extParser;
    }

    /**
     * @param {Stream} input
     * @returns {Object}
     */
    parse(input) {
        return {
            ClientVersion:  this._parseClientVersion(input),
            ClientRandom: this._parseClientRandom(input),
            SessionID: this._parseSessionID(input),
            CipherSuites: this._parseCipherSuites(input),
            CompressionMethods: this._parseCompressionMethods(input),
            Extensions: this._extParser.parse(input)
        };
    }

    /**
     *
     * @param {Stream} inputStream
     */
    _parseCipherSuites(inputStream) {
        const length = inputStream.readInt(2);

        const output = [];

        for (let i = 0; i < length; i+=2) {
            const identifier = inputStream.readInt(2);
            output.push(new KeyValuePair(identifier, cipherSuiteLookup(identifier)));
        }

        return output;
    }

    /**
     *
     * @param {Stream} input
     */
    _parseClientVersion(input) {
        const identifier = input.readInt(2);
        return new KeyValuePair(identifier, versionLookup(identifier));
    }

    /**
     *
     * @param {Stream} input
     */
    _parseClientRandom(input) {
        return "0x" + toHexFast(input.getBytes(32));
    }

    /**
     *
     * @param {Stream} input
     */
    _parseSessionID(input) {
        const length = input.readInt(1);
        return "0x" + toHexFast(input.getBytes(length));
    }

    /**
     *
     * @param {Stream} input
     */
    _parseCompressionMethods(input) {
        const length = input.readInt(1);

        const output = [];

        for (let i = 0; i < length; i+=1) {
            const identifier = input.readInt(1);
            output.push(new KeyValuePair(identifier, compressionMethodLookup(identifier)));
        }

        return output;
    }
}

/**
 *
 */
class ServerHelloParser{

    /**
     *
     * @param {TLSExtensionParser} extParser
     */
    constructor(extParser) {
        this._extParser = extParser;
    }

    /**
     *
     * @param {Stream} input
     * @return {Object}
     */
    parse(input) {
        return {
            ServerVersion: this._serverVersion(input),
            ServerRandom: this._serverRandom(input),
            SessionID: this._sessionID(input),
            CipherSuite: this._cipherSuite(input),
            CompressionMethod: this._compressionMethod(input),
            Extensions: this._extParser.parse(input)
        };
    }

    /**
     *
     * @param {Stream} input
     */
    _serverVersion(input) {
        const identifier = input.readInt(2);
        return new KeyValuePair(identifier, versionLookup(identifier));
    }

    /**
     *
     * @param {Stream} input
     */
    _serverRandom(input) {
        return "0x" + toHexFast(input.getBytes(32));
    }

    /**
     *
     * @param {Stream} input
     */
    _sessionID(input) {
        const length = input.readInt(1);
        return "0x" + toHexFast(input.getBytes(length));
    }

    /**
     *
     * @param {Stream} input
     */
    _cipherSuite(input) {
        const identifier = input.readInt(2);
        return new KeyValuePair(identifier, versionLookup(identifier));
    }

    /**
     *
     * @param {Stream} input
     */
    _compressionMethod(input) {
        const identifier = input.readInt(1);
        return new KeyValuePair(identifier, compressionMethodLookup(identifier));
    }
}

/**
 *
 */
class HandshakeParser {

    /**
     *
     * @param {ClientHelloParser} clientHelloParser
     * @param {ServerHelloParser} serverHelloParser
     */
    constructor(clientHelloParser, serverHelloParser) {
        this._clientHelloParser = clientHelloParser;
        this._serverHelloParser = serverHelloParser;
    }

    /**
     *
     * @param {Stream} input
     */
    parse(input) {
        const type = input.readInt(1);
        const length = input.readInt(3);
        let value;
        switch (type) {
            case HandshakeType.CLIENT_HELLO:
                value = this._clientHelloParser.parse(new Stream(input.getBytes(length)));
                break;
            case HandshakeType.SERVER_HELLO:
                value = this._serverHelloParser.parse(new Stream(input.getBytes(length)));
                break;
            default:
                throw Operation("Unknown Handshake Message Type");
        }
        return {
            Type: type,
            Length: length,
            Value: value
        };
    }
}

/**
 * ParseTLS operation
 */
class ParseTLS extends Operation {

    /**
     * ParseTLS constructor
     */
    constructor() {
        super();

        this.name = "Parse TLS";
        this.module = "Default";
        this.description = "Parses a TLS Message";
        this.infoURL = "";
        this.inputType = "string";
        this.outputType = "json";
        this.args = [
            /* Example arguments. See the project wiki for full details.
            {
                name: "First arg",
                type: "string",
                value: "Don't Panic"
            },
            {
                name: "Second arg",
                type: "number",
                value: 42
            }
            */
        ];
        const clientHelloParser = new ClientHelloParser(new TLSExtensionsParser(HandshakeType.CLIENT_HELLO));
        const serverHelloParser = new ServerHelloParser(new TLSExtensionsParser(HandshakeType.SERVER_HELLO));
        this._handshakeParser = new HandshakeParser(clientHelloParser, serverHelloParser);
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // const [firstArg, secondArg] = args;
        const contentType = {
            CHANGE_CIPHER_SPEC: 20,
            ALERT: 21,
            HANDSHAKE: 22,
            APPLICATION_DATA: 23,
            HEARTBEAT: 24,
            TLS12_CID: 25,
        };

        const contentTypes = new Map();

        for (const key in contentType) {
            contentTypes[contentType[key]] = key.toString().toLowerCase();
        }

        input = new Stream(fromHex(input));

        const output = [];

        while (input.hasMore()) {
            const type = input.readInt(1);
            const protocolVersion = versionLookup(input.readInt(2));
            const length = input.readInt(2);
            const content = input.getBytes(length);
            switch (type) {
                case contentType.HANDSHAKE:
                    output.push({
                        Type: contentTypes[contentType.HANDSHAKE],
                        ProtocolVersion: protocolVersion,
                        Length: length,
                        value: this._handshakeParser.parse(new Stream(content))
                    });
                    break;
                case contentType.CHANGE_CIPHER_SPEC:
                    output.push({
                        Type: contentTypes[contentType.CHANGE_CIPHER_SPEC],
                        ProtocolVersion: protocolVersion,
                        Length: length,
                        value: "0x" + toHexFast(content)
                    });
                    break;
                case contentType.APPLICATION_DATA:
                    output.push({
                        Type: contentTypes[contentType.APPLICATION_DATA],
                        ProtocolVersion: protocolVersion,
                        length: length,
                        value: "0x" + toHexFast(content)
                    });
                    break;
                default:
                    // Unknown types
                    continue;
            }
        }

        return output;
    }
}

export default ParseTLS;
