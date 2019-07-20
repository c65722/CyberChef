/**
 * @author c65722 []
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import {toHexFast} from "../lib/Hex.mjs";
import {objToTable} from "../lib/Protocol.mjs";
import Stream from "../lib/Stream.mjs";

/**
 * Parse TLS record operation.
 */
class ParseTLSRecord extends Operation {

    /**
     * ParseTLSRecord constructor.
     */
    constructor() {
        super();

        this.name = "Parse TLS record";
        this.module = "Default";
        this.description = "Parses one or more TLS records";
        this.infoURL = "https://wikipedia.org/wiki/Transport_Layer_Security";
        this.inputType = "ArrayBuffer";
        this.outputType = "json";
        this.presentType = "html";
        this.args = [];
        this._handshakeParser = new HandshakeParser();
    }

    /**
     * @param {ArrayBuffer} input - Stream, containing one or more raw TLS Records.
     * @param {Object[]} args
     * @returns {Object[]} Array of Object representations of TLS Records contained within input.
     */
    run(input, args) {
        const contentType = {
            CHANGE_CIPHER_SPEC: 20,
            ALERT: 21,
            HANDSHAKE: 22,
            APPLICATION_DATA: 23,
        };

        const contentTypes = new Map();

        for (const key in contentType) {
            contentTypes[contentType[key]] = key.toString().toLowerCase();
        }

        const s = new Stream(new Uint8Array(input));

        const output = [];

        while (s.hasMore()) {
            if (s.position + 5 > s.length) {
                s.moveTo(s.length);
                break;
            }

            // TODO class for this
            const recordHeader = {};

            const type = s.readInt(1);

            recordHeader.type = contentTypes[type] ?? type;
            recordHeader.version = "0x" + toHexFast(s.getBytes(2));
            recordHeader.length = s.readInt(2);

            const content = s.getBytes(recordHeader.length);
            if (content.length < recordHeader.length) {
                recordHeader.truncated = true;
            }


            if (!content.length) {
                const record = {...recordHeader};
                output.push(record);

            } else if (type === contentType.HANDSHAKE) {
                output.push(this._handshakeParser.parse(new Stream(content), recordHeader));

            } else {
                const record = {...recordHeader};
                record.value = "0x" + toHexFast(content);
                output.push(record);
            }
        }

        return output;
    }

    /**
     * Displays the parsed TLS records in a tabular style.
     *
     * @param {Object[]} data - Array of Object representations of the TLS Records.
     * @returns {html} HTML representation of TLS Records contained within data.
     */
    present(data) {
        return data.map(r => objToTable(r)).join("\n\n");
    }
}

export default ParseTLSRecord;

/**
 * Parses TLS Handshake messages.
 */
class HandshakeParser {

    /**
     * HandshakeParser constructor.
     */
    constructor() {
        this._clientHelloParser = new ClientHelloParser();
        this._serverHelloParser = new ServerHelloParser();
        this._newSessionTicketParser = new NewSessionTicketParser();
        this._certificateParser = new CertificateParser();
        this._certificateRequestParser = new CertificateRequestParser();
        this._certificateVerifyParser = new CertificateVerifyParser();
    }

    /**
     * Parses a single TLS handshake message.
     * TODO amend this
     * @param {Stream} input - Stream, containing a raw Handshake message.
     * @returns {Object} Object representation of Handshake.
     */
    parse(input, recordHeader) {
        const HandshakeType = {
            HELLO_REQUEST: 0,
            CLIENT_HELLO: 1,
            SERVER_HELLO: 2,
            NEW_SESSION_TICKET: 4,
            CERTIFICATE: 11,
            SERVER_KEY_EXCHANGE: 12,
            CERTIFICATE_REQUEST: 13,
            SERVER_HELLO_DONE: 14,
            CERTIFICATE_VERIFY: 15,
            CLIENT_KEY_EXCHANGE: 16,
            FINISHED: 20,
        };

        const handshakeTypes = new Map();

        for (const key in HandshakeType) {
            handshakeTypes[HandshakeType[key]] = key.toString().toLocaleLowerCase();
        }

        const output = {...recordHeader};

        if (!input.hasMore()) {
            return output;
        }

        const handshakeType = input.readInt(1);
        output.handshakeType = handshakeTypes[handshakeType] ?? handshakeType;

        // TODO: Bounds checks
        if (input.position + 3 > input.length) {
            input.moveTo(input.length);

            return output;
        }
        const handshakeLength = input.readInt(3);

        if (handshakeLength + 4 !== recordHeader.length) {
            input.moveTo(0);

            output.handshakeType = handshakeTypes[HandshakeType.FINISHED];
            output.handshakeValue = "0x" + toHexFast(input.bytes);

            return output;
        }

        const content = input.getBytes(handshakeLength);
        if (!content.length) {
            return output;
        }

        switch (handshakeType) {
            case HandshakeType.CLIENT_HELLO:
                return {...output, ...this._clientHelloParser.parse(new Stream(content))};
            case HandshakeType.SERVER_HELLO:
                return {...output, ...this._serverHelloParser.parse(new Stream(content))};
            case HandshakeType.NEW_SESSION_TICKET:
                return {...output, ...this._newSessionTicketParser.parse(new Stream(content))};
            case HandshakeType.CERTIFICATE:
                return {...output, ...this._certificateParser.parse(new Stream(content))};
            case HandshakeType.CERTIFICATE_REQUEST:
                return {...output, ...this._certificateRequestParser.parse(new Stream(content))};
            case HandshakeType.CERTIFICATE_VERIFY:
                return {...output, ...this._certificateVerifyParser.parse(new Stream(content))};
            default:
                output.handshakeValue = "0x" + toHexFast(content);
        }

        return output;
    }
}

/**
 * Parses TLS Handshake ClientHello messages.
 */
class ClientHelloParser {

    /**
     * ClientHelloParser constructor.
     */
    constructor() {
        this._extensionsParser = new ExtensionsParser();
    }

    /**
     * Parses a single TLS Handshake ClientHello message.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message.
     * @returns {Object} Object representation of ClientHello.
     */
    parse(input) {
        const output = {};

        output.clientVersion =  this._readClientVersion(input);
        output.random = this._readRandom(input);

        const sessionID = this._readSessionID(input);
        if (sessionID !== null) {
            output.sessionID = sessionID;
        }

        output.cipherSuites = this._readCipherSuites(input);
        output.compressionMethods = this._readCompressionMethods(input);
        output.extensions = this._readExtensions(input);

        return output;
    }

    /**
     * Reads the client_version field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before client_version field.
     * @returns {string} Hex representation of client_version.
     */
    _readClientVersion(input) {
        const version = input.getBytes(2);
        if (!version || version.length !== 2) {
            return "";
        }

        return "0x" + toHexFast(version);
    }

    /**
     * Reads the random field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before random field.
     * @returns {string} Hex representation of random.
     */
    _readRandom(input) {
        const random = input.getBytes(32);
        if (!random || random.length !== 32) {
            return "";
        }

        return "0x" + toHexFast(random);
    }

    /**
     * Reads the session_id field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before session_id length field.
     * @returns {string} Hex representation of session_id, or null if session_id not present.
     */
    _readSessionID(input) {
        const length = input.readInt(1);
        if (!length) {
            return null;
        }

        const sessionID = input.getBytes(length);
        if (!sessionID || sessionID.length !== length) {
            return "";
        }

        return "0x" + toHexFast(sessionID);
    }

    /**
     * Reads the cipher_suites field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before cipher_suites length field.
     * @returns {Object} Object represention of cipher_suites field.
     */
    _readCipherSuites(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const cipherSuites = new Stream(input.getBytes(output.length));
        if (cipherSuites.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (cipherSuites.hasMore()) {
            const cipherSuite = cipherSuites.getBytes(2);
            if (cipherSuite.length === 2) {
                output.values.push("0x" + toHexFast(cipherSuite));
            }
        }

        return output;
    }

    /**
     * Reads the compression_methods field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before compression_methods length field.
     * @returns {Object} Object representation of compression_methods field.
     */
    _readCompressionMethods(input) {
        const output = {};

        output.length = input.readInt(1);
        if (!output.length) {
            return {};
        }

        const compressionMethods = new Stream(input.getBytes(output.length));
        if (compressionMethods.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (compressionMethods.hasMore()) {
            output.values.push("0x" + toHexFast(compressionMethods.getBytes(1)));
        }

        return output;
    }

    /**
     * Reads the extensions field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before extensions length field.
     * @returns {Object} Object representations of extensions field.
     */
    _readExtensions(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const extensions = new Stream(input.getBytes(output.length));
        if (extensions.length < output.length) {
            output.truncated = true;
        }

        output.values = this._extensionsParser.parse(extensions);

        return output;
    }
}

/**
 * Parses TLS Handshake ServeHello messages.
 */
class ServerHelloParser {

    /**
     * ServerHelloParser constructor.
     */
    constructor() {
        this._extensionsParser = new ExtensionsParser();
    }

    /**
     *  Parses a single TLS Handshake ServerHello message.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message.
     * @return {Object} Object representation of ServerHello.
     */
    parse(input) {
        const output = {};

        output.serverVersion = this._readServerVersion(input);
        output.random = this._readRandom(input);

        const sessionID = this._readSessionID(input);
        if (sessionID !== null) {
            output.sessionID = sessionID;
        }

        output.cipherSuite =  this._readCipherSuite(input);
        output.compressionMethod = this._readCompressionMethod(input);
        output.extensions = this._readExtensions(input);

        return output;
    }

    /**
     * Reads the server_version field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before server_version field.
     * @returns {string} Hex representation of server_version.
     */
    _readServerVersion(input) {
        const version = input.getBytes(2);
        if (!version || version.length !== 2) {
            return "";
        }

        return "0x" + toHexFast(version);
    }

    /**
     * Reads the random field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before random field.
     * @returns {string} Hex representation of random.
     */
    _readRandom(input) {
        const random = input.getBytes(32);
        if (!random || random.length !== 32) {
            return "";
        }

        return "0x" + toHexFast(random);
    }

    /**
     * Reads the session_id field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServertHello message, with position before session_id length field.
     * @returns {string} Hex representation of session_id, or null if session_id not present.
     */
    _readSessionID(input) {
        const length = input.readInt(1);
        if (!length) {
            return null;
        }

        const sessionID = input.getBytes(length);
        if (!sessionID || sessionID.length !== length) {
            return "";
        }

        return "0x" + toHexFast(sessionID);
    }

    /**
     * Reads the cipher_suite field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before cipher_suite field.
     * @returns {string} Hex represention of cipher_suite.
     */
    _readCipherSuite(input) {
        const cipherSuite = input.getBytes(2);
        if (!cipherSuite || cipherSuite.length !== 2) {
            return "";
        }

        return "0x" + toHexFast(cipherSuite);
    }

    /**
     * Reads the compression_method field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before compression_method field.
     * @returns {string} Hex represention of compression_method.
     */
    _readCompressionMethod(input) {
        const compressionMethod = input.getBytes(1);
        if (!compressionMethod || compressionMethod.length !== 1) {
            return "";
        }

        return "0x" +  toHexFast(compressionMethod);
    }

    /**
     * Reads the extensions field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before extensions length field.
     * @returns {Object} Object representation of extensions field.
     */
    _readExtensions(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const extensions = new Stream(input.getBytes(output.length));
        if (extensions.length < output.length) {
            output.truncated = true;
        }

        output.values = this._extensionsParser.parse(extensions);

        return output;
    }
}

/**
 * Parses TLS Handshake Hello Extensions.
 */
class ExtensionsParser {

    /**
     * Parses a stream of TLS Handshake Hello Extensions.
     *
     * @param {Stream} input - Stream, containing multiple raw Extensions, with position before first extension length field.
     * @returns {Object[]} Array of Object representations of Extensions contained within input.
     */
    parse(input) {
        const output = [];

        while (input.hasMore()) {
            const extension = this._readExtension(input);
            if (extension) {
                output.push(extension);
            }
        }

        return output;
    }

    /**
     * Reads a single Extension from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a list of Extensions, with position before the length field of the next Extension.
     * @returns {Object} Object representation of Extension.
     */
    _readExtension(input) {
        const output = {};

        // TODO: Bounds checks
        if (input.position + 4 > input.length) {
            input.moveTo(input.length);
            return null;
        }

        output.type = "0x" + toHexFast(input.getBytes(2));
        output.length = input.readInt(2);
        if (!output.length) {
            return output;
        }

        const value = input.getBytes(output.length);
        if (!value || value.length !== output.length) {
            output.truncated = true;
        }

        if (value && value.length) {
            output.value = "0x" + toHexFast(value);
        }

        return output;
    }
}

/**
 * Parses TLS Handshake NewSessionTicket messages.
 */
class NewSessionTicketParser {

    /**
     * Parses a single TLS Handshake NewSessionTicket message.
     *
     * @param {Stream} input - Stream, containing a raw NewSessionTicket message.
     * @returns {Object} Object representation of NewSessionTicket.
     */
    parse(input) {
        return {
            ticketLifetimeHint: this._readTicketLifetimeHint(input),
            ticket: this._readTicket(input),
        };
    }

    /**
     * Reads the ticket_lifetime_hint field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw NewSessionTicket message, with position before ticket_lifetime_hint field.
     * @returns {string} Lifetime hint, in seconds.
     */
    _readTicketLifetimeHint(input) {
        // TODO: Bounds checks
        if (input.position + 4 > input.length) {
            input.moveTo(input.length);
            return "";
        }

        return input.readInt(4) + "s";
    }

    /**
     * Reads the ticket field fromt the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw NewSessionTicket message, with position before ticket length field.
     * @returns {string} Hex representation of ticket.
     */
    _readTicket(input) {
        const length = input.readInt(2);
        if (!length) {
            return "";
        }

        const ticket = input.getBytes(length);
        if (!ticket || ticket.length !== length) {
            return "";
        }

        return "0x" + toHexFast(ticket);
    }
}

/**
 * Parses TLS Handshake Certificate messages.
 */
class CertificateParser {

    /**
     * Parses a single TLS Handshake Certificate message.
     *
     * @param {Stream} input - Stream, containing a raw Certificate message.
     * @returns {Object} Object representation of Certificate.
     */
    parse(input) {
        const output = {};

        output.certificateList = this._readCertificateList(input);

        return output;
    }

    /**
     * Reads the certificate_list field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw Certificate message, with position before certificate_list length field.
     * @returns {string[]} Array of strings, each containing a hex representation of a value within the certificate_list field.
     */
    _readCertificateList(input) {
        const output = {};

        // TODO: Bounds checks
        if (input.position + 3 > input.length) {
            input.moveTo(input.length);
            return output;
        }

        output.length = input.readInt(3);
        if (!output.length) {
            return output;
        }

        const certificates = new Stream(input.getBytes(output.length));
        if (certificates.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (certificates.hasMore()) {
            const certificate = this._readCertificate(certificates);
            if (certificate) {
                output.values.push(certificate);
            }
        }

        return output;
    }

    /**
     * Reads a single certificate from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a list of certificicates, with position before the length field of the next certificate.
     * @returns {string} Hex representation of certificate.
     */
    _readCertificate(input) {
        const length = input.readInt(3);
        if (!length) {
            return "";
        }

        const certificate = input.getBytes(length);
        if (!certificate || certificate.length !== length) {
            return "";
        }

        return "0x" + toHexFast(certificate);
    }
}

/**
 * Parses TLS Handshake CertificateRequest messages.
 */
class CertificateRequestParser {

    /**
     * Parses a single TLS Handshake CertificateRequest message.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message.
     * @return {Object} Object representation of CertificateRequest.
     */
    parse(input) {
        const output = {};

        output.certificateTypes = this._readCertificateTypes(input);
        output.supportedSignatureAlgorithms = this._readSupportedSignatureAlgorithms(input);

        const certificateAuthorities = this._readCertificateAuthorities(input);
        if (certificateAuthorities.length) {
            output.certificateAuthorities = certificateAuthorities;
        }

        return output;
    }

    /**
     * Reads the certificate_types field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message, with position before certificate_types length field.
     * @return {string[]} Array of strings, each containing a hex representation of a value within the certificate_types field.
     */
    _readCertificateTypes(input) {
        const output = {};

        output.length = input.readInt(1);
        if (!output.length) {
            return {};
        }

        const certificateTypes = new Stream(input.getBytes(output.length));
        if (certificateTypes.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (certificateTypes.hasMore()) {
            const certificateType = certificateTypes.getBytes(1);
            if (certificateType) {
                output.values.push("0x" + toHexFast(certificateType));
            }
        }

        return output;
    }

    /**
     * Reads the supported_signature_algorithms field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message, with position before supported_signature_algorithms length field.
     * @returns {string[]} Array of strings, each containing a hex representation of a value within the supported_signature_algorithms field.
     */
    _readSupportedSignatureAlgorithms(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const signatureAlgorithms = new Stream(input.getBytes(output.length));
        if (signatureAlgorithms.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (signatureAlgorithms.hasMore()) {
            const signatureAlgorithm = signatureAlgorithms.getBytes(2);
            if (signatureAlgorithm.length === 2) {
                output.values.push("0x" + toHexFast(signatureAlgorithm));
            }
        }

        return output;
    }

    /**
     * Reads the certificate_authorities field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message, with position before certificate_authorities length field.
     * @returns {string[]} Array of strings, each containing a hex representation of a value within the certificate_authorities field.
     */
    _readCertificateAuthorities(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const certificateAuthorities = new Stream(input.getBytes(output.length));
        if (certificateAuthorities.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (certificateAuthorities.hasMore()) {
            const certificateAuthority = this._readCertificateAuthority(certificateAuthorities);
            if (certificateAuthority) {
                output.values.push(certificateAuthority);
            }
        }

        return output;
    }

    /**
     * Reads a single certificate authority from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a list of raw certificate authorities, with position before the length field of the next certificate authority.
     * @returns {string} Hex representation of certificate authority.
     */
    _readCertificateAuthority(input) {
        const length = input.readInt(2);
        if (!length) {
            return "";
        }

        const certificateAuthority = input.getBytes(length);
        if (!certificateAuthority || certificateAuthority.length !== length) {
            return "";
        }

        return "0x" + toHexFast(certificateAuthority);
    }
}

/**
 * Parses TLS Handshake CertificateVerify messages.
 */
class CertificateVerifyParser {

    /**
     * Parses a single CertificateVerify Message.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message.
     * @returns {Object} Object representation of CertificateVerify.
     */
    parse(input) {
        return {
            algorithmHash: this._readAlgorithmHash(input),
            algorithmSignature: this._readAlgorithmSignature(input),
            signature: this._readSignature(input),
        };
    }

    /**
     * Reads the algorithm.hash field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message, with position before algorithm.hash field.
     * @return {string} Hex representation of hash algorithm.
     */
    _readAlgorithmHash(input) {
        const algorithmHash = input.getBytes(1);
        if (!algorithmHash || algorithmHash.length !== 1) {
            return "";
        }

        return "0x" + toHexFast(algorithmHash);
    }

    /**
     * Reads the algorithm.signature field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message, with position before algorithm.signature field.
     * @return {string} Hex representation of signature algorithm.
     */
    _readAlgorithmSignature(input) {
        const algorithmSignature = input.getBytes(1);
        if (!algorithmSignature || algorithmSignature.length !== 1) {
            return "";
        }

        return  "0x" + toHexFast(algorithmSignature);
    }

    /**
     * Reads the signature field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message, with position before signature field.
     * @return {string} Hex representation of signature.
     */
    _readSignature(input) {
        const length = input.readInt(2);
        if (!length) {
            return "";
        }

        const signature = input.getBytes(length);
        if (!signature || signature.length !== length) {
            return "";
        }

        return "0x" +toHexFast(signature);
    }
}
