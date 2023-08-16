"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// ../../node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js
var require_safe_json_parse = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.safeJsonParse = exports.isJsonObject = void 0;
    function isJsonObject(j) {
      return typeof j === "object" && !Array.isArray(j) && j !== null;
    }
    exports.isJsonObject = isJsonObject;
    function safeJsonParse(s) {
      return JSON.parse(s, (_, value) => {
        if (typeof value === "object" && !Array.isArray(value) && value !== null) {
          delete value.__proto__;
          delete value.constructor;
        }
        return value;
      });
    }
    exports.safeJsonParse = safeJsonParse;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/error.js
var require_error = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/error.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.NonRetryableFetchError = exports.FetchError = exports.JwkInvalidKtyError = exports.JwkInvalidUseError = exports.JwksNotAvailableInCacheError = exports.WaitPeriodNotYetEndedJwkError = exports.KidNotFoundInJwksError = exports.JwtWithoutValidKidError = exports.JwkValidationError = exports.JwksValidationError = exports.Asn1DecodingError = exports.CognitoJwtInvalidClientIdError = exports.CognitoJwtInvalidTokenUseError = exports.CognitoJwtInvalidGroupError = exports.JwtNotBeforeError = exports.JwtExpiredError = exports.JwtInvalidScopeError = exports.JwtInvalidAudienceError = exports.JwtInvalidIssuerError = exports.JwtInvalidClaimError = exports.JwtInvalidSignatureAlgorithmError = exports.JwtInvalidSignatureError = exports.ParameterValidationError = exports.JwtParseError = exports.FailedAssertionError = exports.JwtBaseError = void 0;
    var JwtBaseError = class extends Error {
    };
    exports.JwtBaseError = JwtBaseError;
    var FailedAssertionError = class extends JwtBaseError {
      constructor(msg, actual, expected) {
        super(msg);
        this.failedAssertion = {
          actual,
          expected
        };
      }
    };
    exports.FailedAssertionError = FailedAssertionError;
    var JwtParseError = class extends JwtBaseError {
      constructor(msg, error) {
        const message = error != null ? `${msg}: ${error}` : msg;
        super(message);
      }
    };
    exports.JwtParseError = JwtParseError;
    var ParameterValidationError = class extends JwtBaseError {
    };
    exports.ParameterValidationError = ParameterValidationError;
    var JwtInvalidSignatureError = class extends JwtBaseError {
    };
    exports.JwtInvalidSignatureError = JwtInvalidSignatureError;
    var JwtInvalidSignatureAlgorithmError = class extends FailedAssertionError {
    };
    exports.JwtInvalidSignatureAlgorithmError = JwtInvalidSignatureAlgorithmError;
    var JwtInvalidClaimError = class extends FailedAssertionError {
      withRawJwt({ header, payload }) {
        this.rawJwt = {
          header,
          payload
        };
        return this;
      }
    };
    exports.JwtInvalidClaimError = JwtInvalidClaimError;
    var JwtInvalidIssuerError = class extends JwtInvalidClaimError {
    };
    exports.JwtInvalidIssuerError = JwtInvalidIssuerError;
    var JwtInvalidAudienceError = class extends JwtInvalidClaimError {
    };
    exports.JwtInvalidAudienceError = JwtInvalidAudienceError;
    var JwtInvalidScopeError = class extends JwtInvalidClaimError {
    };
    exports.JwtInvalidScopeError = JwtInvalidScopeError;
    var JwtExpiredError = class extends JwtInvalidClaimError {
    };
    exports.JwtExpiredError = JwtExpiredError;
    var JwtNotBeforeError = class extends JwtInvalidClaimError {
    };
    exports.JwtNotBeforeError = JwtNotBeforeError;
    var CognitoJwtInvalidGroupError = class extends JwtInvalidClaimError {
    };
    exports.CognitoJwtInvalidGroupError = CognitoJwtInvalidGroupError;
    var CognitoJwtInvalidTokenUseError = class extends JwtInvalidClaimError {
    };
    exports.CognitoJwtInvalidTokenUseError = CognitoJwtInvalidTokenUseError;
    var CognitoJwtInvalidClientIdError = class extends JwtInvalidClaimError {
    };
    exports.CognitoJwtInvalidClientIdError = CognitoJwtInvalidClientIdError;
    var Asn1DecodingError = class extends JwtBaseError {
    };
    exports.Asn1DecodingError = Asn1DecodingError;
    var JwksValidationError = class extends JwtBaseError {
    };
    exports.JwksValidationError = JwksValidationError;
    var JwkValidationError = class extends JwtBaseError {
    };
    exports.JwkValidationError = JwkValidationError;
    var JwtWithoutValidKidError = class extends JwtBaseError {
    };
    exports.JwtWithoutValidKidError = JwtWithoutValidKidError;
    var KidNotFoundInJwksError = class extends JwtBaseError {
    };
    exports.KidNotFoundInJwksError = KidNotFoundInJwksError;
    var WaitPeriodNotYetEndedJwkError = class extends JwtBaseError {
    };
    exports.WaitPeriodNotYetEndedJwkError = WaitPeriodNotYetEndedJwkError;
    var JwksNotAvailableInCacheError = class extends JwtBaseError {
    };
    exports.JwksNotAvailableInCacheError = JwksNotAvailableInCacheError;
    var JwkInvalidUseError = class extends FailedAssertionError {
    };
    exports.JwkInvalidUseError = JwkInvalidUseError;
    var JwkInvalidKtyError = class extends FailedAssertionError {
    };
    exports.JwkInvalidKtyError = JwkInvalidKtyError;
    var FetchError = class extends JwtBaseError {
      constructor(uri, msg) {
        super(`Failed to fetch ${uri}: ${msg}`);
      }
    };
    exports.FetchError = FetchError;
    var NonRetryableFetchError = class extends FetchError {
    };
    exports.NonRetryableFetchError = NonRetryableFetchError;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/https.js
var require_https = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/https.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.fetchJson = exports.SimpleJsonFetcher = void 0;
    var https_1 = require("https");
    var stream_1 = require("stream");
    var util_1 = require("util");
    var safe_json_parse_js_1 = require_safe_json_parse();
    var error_js_1 = require_error();
    var SimpleJsonFetcher = class {
      constructor(props) {
        this.defaultRequestOptions = {
          timeout: 500,
          responseTimeout: 1500,
          ...props?.defaultRequestOptions
        };
      }
      /**
       * Execute a HTTPS request (with 1 immediate retry in case of errors)
       * @param uri - The URI
       * @param requestOptions - The RequestOptions to use
       * @param data - Data to send to the URI (e.g. POST data)
       * @returns - The response as parsed JSON
       */
      async fetch(uri, requestOptions, data) {
        requestOptions = { ...this.defaultRequestOptions, ...requestOptions };
        try {
          return await fetchJson(uri, requestOptions, data);
        } catch (err) {
          if (err instanceof error_js_1.NonRetryableFetchError) {
            throw err;
          }
          return fetchJson(uri, requestOptions, data);
        }
      }
    };
    exports.SimpleJsonFetcher = SimpleJsonFetcher;
    async function fetchJson(uri, requestOptions, data) {
      let responseTimeout;
      return new Promise((resolve, reject) => {
        const req = (0, https_1.request)(uri, {
          method: "GET",
          ...requestOptions
        }, (response) => {
          stream_1.pipeline([
            response,
            getJsonDestination(uri, response.statusCode, response.headers)
          ], done);
        });
        if (requestOptions?.responseTimeout) {
          responseTimeout = setTimeout(() => done(new error_js_1.FetchError(uri, `Response time-out (after ${requestOptions.responseTimeout} ms.)`)), requestOptions.responseTimeout);
          responseTimeout.unref();
        }
        function done(...args) {
          if (responseTimeout)
            clearTimeout(responseTimeout);
          if (args[0] == null) {
            resolve(args[1]);
            return;
          }
          req.socket?.emit("agentRemove");
          let error = args[0];
          if (!(error instanceof error_js_1.FetchError)) {
            error = new error_js_1.FetchError(uri, error.message);
          }
          req.destroy();
          reject(error);
        }
        req.on("error", done);
        req.end(data);
      });
    }
    exports.fetchJson = fetchJson;
    function getJsonDestination(uri, statusCode, headers) {
      return async (responseIterable) => {
        if (statusCode === 429) {
          throw new error_js_1.FetchError(uri, "Too many requests");
        } else if (statusCode !== 200) {
          throw new error_js_1.NonRetryableFetchError(uri, `Status code is ${statusCode}, expected 200`);
        }
        if (!headers["content-type"]?.toLowerCase().startsWith("application/json")) {
          throw new error_js_1.NonRetryableFetchError(uri, `Content-type is "${headers["content-type"]}", expected "application/json"`);
        }
        const collected = [];
        for await (const chunk of responseIterable) {
          collected.push(chunk);
        }
        try {
          return (0, safe_json_parse_js_1.safeJsonParse)(new util_1.TextDecoder("utf8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(collected)));
        } catch (err) {
          throw new error_js_1.NonRetryableFetchError(uri, err);
        }
      };
    }
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/jwk.js
var require_jwk = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/jwk.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.SimpleJwksCache = exports.SimplePenaltyBox = exports.isJwk = exports.isJwks = exports.assertIsJwk = exports.assertIsJwks = exports.fetchJwk = exports.fetchJwks = void 0;
    var https_js_1 = require_https();
    var safe_json_parse_js_1 = require_safe_json_parse();
    var error_js_1 = require_error();
    var optionalJwkFieldNames = [
      "alg"
      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    ];
    var mandatoryJwkFieldNames = [
      "e",
      "kid",
      "kty",
      "n",
      "use"
      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2 NOTE: considered mandatory by this library
    ];
    async function fetchJwks(jwksUri) {
      const jwks = await (0, https_js_1.fetchJson)(jwksUri);
      assertIsJwks(jwks);
      return jwks;
    }
    exports.fetchJwks = fetchJwks;
    async function fetchJwk(jwksUri, decomposedJwt) {
      if (!decomposedJwt.header.kid) {
        throw new error_js_1.JwtWithoutValidKidError("JWT header does not have valid kid claim");
      }
      const jwk = (await fetchJwks(jwksUri)).keys.find((key) => key.kid === decomposedJwt.header.kid);
      if (!jwk) {
        throw new error_js_1.KidNotFoundInJwksError(`JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`);
      }
      return jwk;
    }
    exports.fetchJwk = fetchJwk;
    function assertIsJwks(jwks) {
      if (!jwks) {
        throw new error_js_1.JwksValidationError("JWKS empty");
      }
      if (!(0, safe_json_parse_js_1.isJsonObject)(jwks)) {
        throw new error_js_1.JwksValidationError("JWKS should be an object");
      }
      if (!Object.keys(jwks).includes("keys")) {
        throw new error_js_1.JwksValidationError("JWKS does not include keys");
      }
      if (!Array.isArray(jwks.keys)) {
        throw new error_js_1.JwksValidationError("JWKS keys should be an array");
      }
      for (const jwk of jwks.keys) {
        assertIsJwk(jwk);
      }
    }
    exports.assertIsJwks = assertIsJwks;
    function assertIsJwk(jwk) {
      if (!jwk) {
        throw new error_js_1.JwkValidationError("JWK empty");
      }
      if (!(0, safe_json_parse_js_1.isJsonObject)(jwk)) {
        throw new error_js_1.JwkValidationError("JWK should be an object");
      }
      for (const field of mandatoryJwkFieldNames) {
        if (typeof jwk[field] !== "string") {
          throw new error_js_1.JwkValidationError(`JWK ${field} should be a string`);
        }
      }
      for (const field of optionalJwkFieldNames) {
        if (field in jwk && typeof jwk[field] !== "string") {
          throw new error_js_1.JwkValidationError(`JWK ${field} should be a string`);
        }
      }
    }
    exports.assertIsJwk = assertIsJwk;
    function isJwks(jwks) {
      try {
        assertIsJwks(jwks);
        return true;
      } catch {
        return false;
      }
    }
    exports.isJwks = isJwks;
    function isJwk(jwk) {
      try {
        assertIsJwk(jwk);
        return true;
      } catch {
        return false;
      }
    }
    exports.isJwk = isJwk;
    var SimplePenaltyBox = class {
      constructor(props) {
        this.waitingUris = /* @__PURE__ */ new Map();
        this.waitSeconds = props?.waitSeconds ?? 10;
      }
      async wait(jwksUri) {
        if (this.waitingUris.has(jwksUri)) {
          throw new error_js_1.WaitPeriodNotYetEndedJwkError("Not allowed to fetch JWKS yet, still waiting for back off period to end");
        }
      }
      release(jwksUri) {
        const i = this.waitingUris.get(jwksUri);
        if (i) {
          clearTimeout(i);
          this.waitingUris.delete(jwksUri);
        }
      }
      registerFailedAttempt(jwksUri) {
        const i = setTimeout(() => {
          this.waitingUris.delete(jwksUri);
        }, this.waitSeconds * 1e3).unref();
        this.waitingUris.set(jwksUri, i);
      }
      registerSuccessfulAttempt(jwksUri) {
        this.release(jwksUri);
      }
    };
    exports.SimplePenaltyBox = SimplePenaltyBox;
    var SimpleJwksCache = class {
      constructor(props) {
        this.jwksCache = /* @__PURE__ */ new Map();
        this.fetchingJwks = /* @__PURE__ */ new Map();
        this.penaltyBox = props?.penaltyBox ?? new SimplePenaltyBox();
        this.fetcher = props?.fetcher ?? new https_js_1.SimpleJsonFetcher();
      }
      addJwks(jwksUri, jwks) {
        this.jwksCache.set(jwksUri, jwks);
      }
      async getJwks(jwksUri) {
        const existingFetch = this.fetchingJwks.get(jwksUri);
        if (existingFetch) {
          return existingFetch;
        }
        const jwksPromise = this.fetcher.fetch(jwksUri).then((res) => {
          assertIsJwks(res);
          return res;
        });
        this.fetchingJwks.set(jwksUri, jwksPromise);
        let jwks;
        try {
          jwks = await jwksPromise;
        } finally {
          this.fetchingJwks.delete(jwksUri);
        }
        this.jwksCache.set(jwksUri, jwks);
        return jwks;
      }
      getCachedJwk(jwksUri, decomposedJwt) {
        if (typeof decomposedJwt.header.kid !== "string") {
          throw new error_js_1.JwtWithoutValidKidError("JWT header does not have valid kid claim");
        }
        if (!this.jwksCache.has(jwksUri)) {
          throw new error_js_1.JwksNotAvailableInCacheError(`JWKS for uri ${jwksUri} not yet available in cache`);
        }
        const jwk = this.jwksCache.get(jwksUri).keys.find((key) => key.kid === decomposedJwt.header.kid);
        if (!jwk) {
          throw new error_js_1.KidNotFoundInJwksError(`JWK for kid ${decomposedJwt.header.kid} not found in the JWKS`);
        }
        return jwk;
      }
      async getJwk(jwksUri, decomposedJwt) {
        if (typeof decomposedJwt.header.kid !== "string") {
          throw new error_js_1.JwtWithoutValidKidError("JWT header does not have valid kid claim");
        }
        let jwk = this.jwksCache.get(jwksUri)?.keys.find((key) => key.kid === decomposedJwt.header.kid);
        if (jwk) {
          return jwk;
        }
        await this.penaltyBox.wait(jwksUri, decomposedJwt.header.kid);
        const jwks = await this.getJwks(jwksUri);
        jwk = jwks.keys.find((key) => key.kid === decomposedJwt.header.kid);
        if (!jwk) {
          this.penaltyBox.registerFailedAttempt(jwksUri, decomposedJwt.header.kid);
          throw new error_js_1.KidNotFoundInJwksError(`JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`);
        } else {
          this.penaltyBox.registerSuccessfulAttempt(jwksUri, decomposedJwt.header.kid);
        }
        return jwk;
      }
    };
    exports.SimpleJwksCache = SimpleJwksCache;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/asn1.js
var require_asn1 = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/asn1.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.deconstructPublicKeyInDerFormat = exports.constructPublicKeyInDerFormat = void 0;
    var error_js_1 = require_error();
    var Asn1Class;
    (function(Asn1Class2) {
      Asn1Class2[Asn1Class2["Universal"] = 0] = "Universal";
    })(Asn1Class || (Asn1Class = {}));
    var Asn1Encoding;
    (function(Asn1Encoding2) {
      Asn1Encoding2[Asn1Encoding2["Primitive"] = 0] = "Primitive";
      Asn1Encoding2[Asn1Encoding2["Constructed"] = 1] = "Constructed";
    })(Asn1Encoding || (Asn1Encoding = {}));
    var Asn1Tag;
    (function(Asn1Tag2) {
      Asn1Tag2[Asn1Tag2["BitString"] = 3] = "BitString";
      Asn1Tag2[Asn1Tag2["ObjectIdentifier"] = 6] = "ObjectIdentifier";
      Asn1Tag2[Asn1Tag2["Sequence"] = 16] = "Sequence";
      Asn1Tag2[Asn1Tag2["Null"] = 5] = "Null";
      Asn1Tag2[Asn1Tag2["Integer"] = 2] = "Integer";
    })(Asn1Tag || (Asn1Tag = {}));
    function encodeIdentifier(identifier) {
      const identifierAsNumber = identifier.class << 7 | identifier.primitiveOrConstructed << 5 | identifier.tag;
      return Buffer.from([identifierAsNumber]);
    }
    function encodeLength(length) {
      if (length < 128) {
        return Buffer.from([length]);
      }
      const integers = [];
      while (length > 0) {
        integers.push(length % 256);
        length = length >> 8;
      }
      integers.reverse();
      return Buffer.from([128 | integers.length, ...integers]);
    }
    function encodeBufferAsInteger(buffer) {
      return Buffer.concat([
        encodeIdentifier({
          class: Asn1Class.Universal,
          primitiveOrConstructed: Asn1Encoding.Primitive,
          tag: Asn1Tag.Integer
        }),
        encodeLength(buffer.length),
        buffer
      ]);
    }
    function encodeObjectIdentifier(oid) {
      const oidComponents = oid.split(".").map((i) => parseInt(i));
      const firstSubidentifier = oidComponents[0] * 40 + oidComponents[1];
      const subsequentSubidentifiers = oidComponents.slice(2).reduce((expanded, component) => {
        const bytes = [];
        do {
          bytes.push(component % 128);
          component = component >> 7;
        } while (component);
        return expanded.concat(bytes.map((b, index) => index ? b + 128 : b).reverse());
      }, []);
      const oidBuffer = Buffer.from([
        firstSubidentifier,
        ...subsequentSubidentifiers
      ]);
      return Buffer.concat([
        encodeIdentifier({
          class: Asn1Class.Universal,
          primitiveOrConstructed: Asn1Encoding.Primitive,
          tag: Asn1Tag.ObjectIdentifier
        }),
        encodeLength(oidBuffer.length),
        oidBuffer
      ]);
    }
    function encodeBufferAsBitString(buffer) {
      const bitString = Buffer.concat([Buffer.from([0]), buffer]);
      return Buffer.concat([
        encodeIdentifier({
          class: Asn1Class.Universal,
          primitiveOrConstructed: Asn1Encoding.Primitive,
          tag: Asn1Tag.BitString
        }),
        encodeLength(bitString.length),
        bitString
      ]);
    }
    function encodeSequence(sequenceItems) {
      const concatenated = Buffer.concat(sequenceItems);
      return Buffer.concat([
        encodeIdentifier({
          class: Asn1Class.Universal,
          primitiveOrConstructed: Asn1Encoding.Constructed,
          tag: Asn1Tag.Sequence
        }),
        encodeLength(concatenated.length),
        concatenated
      ]);
    }
    function encodeNull() {
      return Buffer.concat([
        encodeIdentifier({
          class: Asn1Class.Universal,
          primitiveOrConstructed: Asn1Encoding.Primitive,
          tag: Asn1Tag.Null
        }),
        encodeLength(0)
      ]);
    }
    var ALGORITHM_RSA_ENCRYPTION = encodeSequence([
      encodeObjectIdentifier("1.2.840.113549.1.1.1"),
      encodeNull()
      // parameters
    ]);
    function constructPublicKeyInDerFormat(n, e) {
      return encodeSequence([
        ALGORITHM_RSA_ENCRYPTION,
        encodeBufferAsBitString(encodeSequence([encodeBufferAsInteger(n), encodeBufferAsInteger(e)]))
      ]);
    }
    exports.constructPublicKeyInDerFormat = constructPublicKeyInDerFormat;
    function decodeIdentifier(identifier) {
      if (identifier >> 3 === 31) {
        throw new error_js_1.Asn1DecodingError("Decoding of identifier with tag > 30 not implemented");
      }
      return {
        class: identifier >> 6,
        primitiveOrConstructed: identifier >> 5 & 1,
        tag: identifier & 31
        // bit 1-5
      };
    }
    function decodeLengthValue(blockOfLengthValues) {
      if (!(blockOfLengthValues[0] & 128)) {
        return {
          length: blockOfLengthValues[0],
          firstByteOffset: 1,
          lastByteOffset: 1 + blockOfLengthValues[0]
        };
      }
      const nrLengthOctets = blockOfLengthValues[0] & 127;
      const length = Buffer.from(blockOfLengthValues.slice(1, 1 + 1 + nrLengthOctets)).readUIntBE(0, nrLengthOctets);
      return {
        length,
        firstByteOffset: 1 + nrLengthOctets,
        lastByteOffset: 1 + nrLengthOctets + length
      };
    }
    function decodeSequence(sequence) {
      const { tag } = decodeIdentifier(sequence[0]);
      if (tag !== Asn1Tag.Sequence) {
        throw new error_js_1.Asn1DecodingError(`Expected a sequence to decode, but got tag ${tag}`);
      }
      const { firstByteOffset, lastByteOffset } = decodeLengthValue(sequence.slice(1));
      const sequenceValue = sequence.slice(1 + firstByteOffset, 1 + 1 + lastByteOffset);
      const parts = [];
      let offset = 0;
      while (offset < sequenceValue.length) {
        const identifier = decodeIdentifier(sequenceValue[offset]);
        const next = decodeLengthValue(sequenceValue.slice(offset + 1));
        const value = sequenceValue.slice(offset + 1 + next.firstByteOffset, offset + 1 + next.lastByteOffset);
        parts.push({ identifier, length: next.length, value });
        offset += 1 + next.lastByteOffset;
      }
      return parts;
    }
    function decodeBitStringWrappedSequenceValue(bitStringValue) {
      const wrappedSequence = bitStringValue.slice(1);
      return decodeSequence(wrappedSequence);
    }
    function deconstructPublicKeyInDerFormat(publicKey) {
      const [, pubkeyinfo] = decodeSequence(publicKey);
      const [n, e] = decodeBitStringWrappedSequenceValue(pubkeyinfo.value);
      return { n: n.value, e: e.value };
    }
    exports.deconstructPublicKeyInDerFormat = deconstructPublicKeyInDerFormat;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/assert.js
var require_assert = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/assert.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.assertIsNotPromise = exports.assertStringArraysOverlap = exports.assertStringArrayContainsString = exports.assertStringEquals = void 0;
    var error_js_1 = require_error();
    function assertStringEquals(name, actual, expected, errorConstructor = error_js_1.FailedAssertionError) {
      if (!actual) {
        throw new errorConstructor(`Missing ${name}. Expected: ${expected}`, actual, expected);
      }
      if (typeof actual !== "string") {
        throw new errorConstructor(`${name} is not of type string`, actual, expected);
      }
      if (expected !== actual) {
        throw new errorConstructor(`${name} not allowed: ${actual}. Expected: ${expected}`, actual, expected);
      }
    }
    exports.assertStringEquals = assertStringEquals;
    function assertStringArrayContainsString(name, actual, expected, errorConstructor = error_js_1.FailedAssertionError) {
      if (!actual) {
        throw new errorConstructor(`Missing ${name}. ${expectationMessage(expected)}`, actual, expected);
      }
      if (typeof actual !== "string") {
        throw new errorConstructor(`${name} is not of type string`, actual, expected);
      }
      return assertStringArraysOverlap(name, actual, expected, errorConstructor);
    }
    exports.assertStringArrayContainsString = assertStringArrayContainsString;
    function assertStringArraysOverlap(name, actual, expected, errorConstructor = error_js_1.FailedAssertionError) {
      if (!actual) {
        throw new errorConstructor(`Missing ${name}. ${expectationMessage(expected)}`, actual, expected);
      }
      const expectedAsSet = new Set(Array.isArray(expected) ? expected : [expected]);
      if (typeof actual === "string") {
        actual = [actual];
      }
      if (!Array.isArray(actual)) {
        throw new errorConstructor(`${name} is not an array`, actual, expected);
      }
      const overlaps = actual.some((actualItem) => {
        if (typeof actualItem !== "string") {
          throw new errorConstructor(`${name} includes elements that are not of type string`, actual, expected);
        }
        return expectedAsSet.has(actualItem);
      });
      if (!overlaps) {
        throw new errorConstructor(`${name} not allowed: ${actual.join(", ")}. ${expectationMessage(expected)}`, actual, expected);
      }
    }
    exports.assertStringArraysOverlap = assertStringArraysOverlap;
    function expectationMessage(expected) {
      if (Array.isArray(expected)) {
        if (expected.length > 1) {
          return `Expected one of: ${expected.join(", ")}`;
        }
        return `Expected: ${expected[0]}`;
      }
      return `Expected: ${expected}`;
    }
    function assertIsNotPromise(actual, errorFactory) {
      if (actual && typeof actual.then === "function") {
        throw errorFactory();
      }
    }
    exports.assertIsNotPromise = assertIsNotPromise;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/jwt.js
var require_jwt = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/jwt.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.validateJwtFields = exports.decomposeJwt = void 0;
    var assert_js_1 = require_assert();
    var safe_json_parse_js_1 = require_safe_json_parse();
    var error_js_1 = require_error();
    function assertJwtHeader(header) {
      if (!(0, safe_json_parse_js_1.isJsonObject)(header)) {
        throw new error_js_1.JwtParseError("JWT header is not an object");
      }
      if (header.alg !== void 0 && typeof header.alg !== "string") {
        throw new error_js_1.JwtParseError("JWT header alg claim is not a string");
      }
      if (header.kid !== void 0 && typeof header.kid !== "string") {
        throw new error_js_1.JwtParseError("JWT header kid claim is not a string");
      }
    }
    function assertJwtPayload(payload) {
      if (!(0, safe_json_parse_js_1.isJsonObject)(payload)) {
        throw new error_js_1.JwtParseError("JWT payload is not an object");
      }
      if (payload.exp !== void 0 && !Number.isFinite(payload.exp)) {
        throw new error_js_1.JwtParseError("JWT payload exp claim is not a number");
      }
      if (payload.iss !== void 0 && typeof payload.iss !== "string") {
        throw new error_js_1.JwtParseError("JWT payload iss claim is not a string");
      }
      if (payload.aud !== void 0 && typeof payload.aud !== "string" && (!Array.isArray(payload.aud) || payload.aud.some((aud) => typeof aud !== "string"))) {
        throw new error_js_1.JwtParseError("JWT payload aud claim is not a string or array of strings");
      }
      if (payload.nbf !== void 0 && !Number.isFinite(payload.nbf)) {
        throw new error_js_1.JwtParseError("JWT payload nbf claim is not a number");
      }
      if (payload.iat !== void 0 && !Number.isFinite(payload.iat)) {
        throw new error_js_1.JwtParseError("JWT payload iat claim is not a number");
      }
      if (payload.scope !== void 0 && typeof payload.scope !== "string") {
        throw new error_js_1.JwtParseError("JWT payload scope claim is not a string");
      }
      if (payload.jti !== void 0 && typeof payload.jti !== "string") {
        throw new error_js_1.JwtParseError("JWT payload jti claim is not a string");
      }
    }
    function decomposeJwt(jwt) {
      if (!jwt) {
        throw new error_js_1.JwtParseError("Empty JWT");
      }
      if (typeof jwt !== "string") {
        throw new error_js_1.JwtParseError("JWT is not a string");
      }
      if (!jwt.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) {
        throw new error_js_1.JwtParseError("JWT string does not consist of exactly 3 parts (header, payload, signature)");
      }
      const [headerB64, payloadB64, signatureB64] = jwt.split(".");
      const [headerString, payloadString] = [headerB64, payloadB64].map((b64) => Buffer.from(b64, "base64").toString("utf8"));
      let header;
      try {
        header = (0, safe_json_parse_js_1.safeJsonParse)(headerString);
      } catch (err) {
        throw new error_js_1.JwtParseError("Invalid JWT. Header is not a valid JSON object", err);
      }
      assertJwtHeader(header);
      let payload;
      try {
        payload = (0, safe_json_parse_js_1.safeJsonParse)(payloadString);
      } catch (err) {
        throw new error_js_1.JwtParseError("Invalid JWT. Payload is not a valid JSON object", err);
      }
      assertJwtPayload(payload);
      return {
        header,
        headerB64,
        payload,
        payloadB64,
        signatureB64
      };
    }
    exports.decomposeJwt = decomposeJwt;
    function validateJwtFields(payload, options) {
      if (payload.exp !== void 0) {
        if (payload.exp + (options.graceSeconds ?? 0) < Date.now() / 1e3) {
          throw new error_js_1.JwtExpiredError(`Token expired at ${new Date(payload.exp * 1e3).toISOString()}`, payload.exp);
        }
      }
      if (payload.nbf !== void 0) {
        if (payload.nbf - (options.graceSeconds ?? 0) > Date.now() / 1e3) {
          throw new error_js_1.JwtNotBeforeError(`Token can't be used before ${new Date(payload.nbf * 1e3).toISOString()}`, payload.nbf);
        }
      }
      if (options.issuer !== null) {
        if (options.issuer === void 0) {
          throw new error_js_1.ParameterValidationError("issuer must be provided or set to null explicitly");
        }
        (0, assert_js_1.assertStringArrayContainsString)("Issuer", payload.iss, options.issuer, error_js_1.JwtInvalidIssuerError);
      }
      if (options.audience !== null) {
        if (options.audience === void 0) {
          throw new error_js_1.ParameterValidationError("audience must be provided or set to null explicitly");
        }
        (0, assert_js_1.assertStringArraysOverlap)("Audience", payload.aud, options.audience, error_js_1.JwtInvalidAudienceError);
      }
      if (options.scope != null) {
        (0, assert_js_1.assertStringArraysOverlap)("Scope", payload.scope?.split(" "), options.scope, error_js_1.JwtInvalidScopeError);
      }
    }
    exports.validateJwtFields = validateJwtFields;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/jwt-rsa.js
var require_jwt_rsa = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/jwt-rsa.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.KeyObjectCache = exports.transformJwkToKeyObject = exports.JwtRsaVerifier = exports.JwtRsaVerifierBase = exports.verifyJwtSync = exports.verifyJwt = exports.JwtSignatureAlgorithms = void 0;
    var crypto_1 = require("crypto");
    var url_1 = require("url");
    var path_1 = require("path");
    var jwk_js_1 = require_jwk();
    var asn1_js_1 = require_asn1();
    var assert_js_1 = require_assert();
    var jwt_js_1 = require_jwt();
    var error_js_1 = require_error();
    var JwtSignatureAlgorithms;
    (function(JwtSignatureAlgorithms2) {
      JwtSignatureAlgorithms2["RS256"] = "RSA-SHA256";
      JwtSignatureAlgorithms2["RS384"] = "RSA-SHA384";
      JwtSignatureAlgorithms2["RS512"] = "RSA-SHA512";
    })(JwtSignatureAlgorithms = exports.JwtSignatureAlgorithms || (exports.JwtSignatureAlgorithms = {}));
    function verifySignatureAgainstJwk(header, headerB64, payload, payloadB64, signatureB64, jwk, jwkToKeyObjectTransformer = exports.transformJwkToKeyObject) {
      (0, assert_js_1.assertStringEquals)("JWK use", jwk.use, "sig", error_js_1.JwkInvalidUseError);
      (0, assert_js_1.assertStringEquals)("JWK kty", jwk.kty, "RSA", error_js_1.JwkInvalidKtyError);
      if (jwk.alg) {
        (0, assert_js_1.assertStringEquals)("JWT signature algorithm", header.alg, jwk.alg, error_js_1.JwtInvalidSignatureAlgorithmError);
      }
      (0, assert_js_1.assertStringArrayContainsString)("JWT signature algorithm", header.alg, ["RS256", "RS384", "RS512"], error_js_1.JwtInvalidSignatureAlgorithmError);
      const publicKey = jwkToKeyObjectTransformer(jwk, payload.iss, header.kid);
      const valid = (0, crypto_1.createVerify)(JwtSignatureAlgorithms[header.alg]).update(`${headerB64}.${payloadB64}`).verify(publicKey, signatureB64, "base64");
      if (!valid) {
        throw new error_js_1.JwtInvalidSignatureError("Invalid signature");
      }
    }
    async function verifyJwt(jwt, jwksUri, options, jwkFetcher, jwkToKeyObjectTransformer) {
      return verifyDecomposedJwt((0, jwt_js_1.decomposeJwt)(jwt), jwksUri, options, jwkFetcher, jwkToKeyObjectTransformer);
    }
    exports.verifyJwt = verifyJwt;
    async function verifyDecomposedJwt(decomposedJwt, jwksUri, options, jwkFetcher = jwk_js_1.fetchJwk, jwkToKeyObjectTransformer) {
      const { header, headerB64, payload, payloadB64, signatureB64 } = decomposedJwt;
      const jwk = await jwkFetcher(jwksUri, decomposedJwt);
      verifySignatureAgainstJwk(header, headerB64, payload, payloadB64, signatureB64, jwk, jwkToKeyObjectTransformer);
      try {
        (0, jwt_js_1.validateJwtFields)(payload, options);
        if (options.customJwtCheck) {
          await options.customJwtCheck({ header, payload, jwk });
        }
      } catch (err) {
        if (options.includeRawJwtInErrors && err instanceof error_js_1.JwtInvalidClaimError) {
          throw err.withRawJwt(decomposedJwt);
        }
        throw err;
      }
      return payload;
    }
    function verifyJwtSync(jwt, jwkOrJwks, options, jwkToKeyObjectTransformer) {
      return verifyDecomposedJwtSync((0, jwt_js_1.decomposeJwt)(jwt), jwkOrJwks, options, jwkToKeyObjectTransformer);
    }
    exports.verifyJwtSync = verifyJwtSync;
    function verifyDecomposedJwtSync(decomposedJwt, jwkOrJwks, options, jwkToKeyObjectTransformer) {
      const { header, headerB64, payload, payloadB64, signatureB64 } = decomposedJwt;
      let jwk;
      if ((0, jwk_js_1.isJwk)(jwkOrJwks)) {
        jwk = jwkOrJwks;
      } else if ((0, jwk_js_1.isJwks)(jwkOrJwks)) {
        const locatedJwk = jwkOrJwks.keys.find((key) => key.kid === header.kid);
        if (!locatedJwk) {
          throw new error_js_1.KidNotFoundInJwksError(`JWK for kid ${header.kid} not found in the JWKS`);
        }
        jwk = locatedJwk;
      } else {
        throw new error_js_1.ParameterValidationError([
          `Expected a valid JWK or JWKS (parsed as JavaScript object), but received: ${jwkOrJwks}.`,
          "If you're passing a JWKS URI, use the async verify() method instead, it will download and parse the JWKS for you"
        ].join());
      }
      verifySignatureAgainstJwk(header, headerB64, payload, payloadB64, signatureB64, jwk, jwkToKeyObjectTransformer);
      try {
        (0, jwt_js_1.validateJwtFields)(payload, options);
        if (options.customJwtCheck) {
          const res = options.customJwtCheck({ header, payload, jwk });
          (0, assert_js_1.assertIsNotPromise)(res, () => new error_js_1.ParameterValidationError("Custom JWT checks must be synchronous but a promise was returned"));
        }
      } catch (err) {
        if (options.includeRawJwtInErrors && err instanceof error_js_1.JwtInvalidClaimError) {
          throw err.withRawJwt(decomposedJwt);
        }
        throw err;
      }
      return payload;
    }
    var JwtRsaVerifierBase = class {
      constructor(verifyProperties, jwksCache = new jwk_js_1.SimpleJwksCache()) {
        this.jwksCache = jwksCache;
        this.issuersConfig = /* @__PURE__ */ new Map();
        this.publicKeyCache = new KeyObjectCache();
        if (Array.isArray(verifyProperties)) {
          if (!verifyProperties.length) {
            throw new error_js_1.ParameterValidationError("Provide at least one issuer configuration");
          }
          for (const prop of verifyProperties) {
            if (this.issuersConfig.has(prop.issuer)) {
              throw new error_js_1.ParameterValidationError(`issuer ${prop.issuer} supplied multiple times`);
            }
            this.issuersConfig.set(prop.issuer, this.withJwksUri(prop));
          }
        } else {
          this.issuersConfig.set(verifyProperties.issuer, this.withJwksUri(verifyProperties));
        }
      }
      get expectedIssuers() {
        return Array.from(this.issuersConfig.keys());
      }
      getIssuerConfig(issuer) {
        if (!issuer) {
          if (this.issuersConfig.size !== 1) {
            throw new error_js_1.ParameterValidationError("issuer must be provided");
          }
          issuer = this.issuersConfig.keys().next().value;
        }
        const config = this.issuersConfig.get(issuer);
        if (!config) {
          throw new error_js_1.ParameterValidationError(`issuer not configured: ${issuer}`);
        }
        return config;
      }
      /**
       * This method loads a JWKS that you provide, into the JWKS cache, so that it is
       * available for JWT verification. Use this method to speed up the first JWT verification
       * (when the JWKS would otherwise have to be downloaded from the JWKS uri), or to provide the JWKS
       * in case the JwtVerifier does not have internet access to download the JWKS
       *
       * @param jwksThe JWKS
       * @param issuer The issuer for which you want to cache the JWKS
       *  Supply this field, if you instantiated the JwtVerifier with multiple issuers
       * @returns void
       */
      cacheJwks(...[jwks, issuer]) {
        const issuerConfig = this.getIssuerConfig(issuer);
        this.jwksCache.addJwks(issuerConfig.jwksUri, jwks);
        this.publicKeyCache.clearCache(issuerConfig.issuer);
      }
      /**
       * Hydrate the JWKS cache for (all of) the configured issuer(s).
       * This will fetch and cache the latest and greatest JWKS for concerned issuer(s).
       *
       * @param issuer The issuer to fetch the JWKS for
       * @returns void
       */
      async hydrate() {
        const jwksFetches = this.expectedIssuers.map((issuer) => this.getIssuerConfig(issuer).jwksUri).map((jwksUri) => this.jwksCache.getJwks(jwksUri));
        await Promise.all(jwksFetches);
      }
      /**
       * Verify (synchronously) a JWT that is signed using RS256 / RS384 / RS512.
       *
       * @param jwt The JWT, as string
       * @param props Verification properties
       * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
       */
      verifySync(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        return this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
      }
      /**
       * Verify (synchronously) an already decomposed JWT, that is signed using RS256 / RS384 / RS512.
       *
       * @param decomposedJwt The decomposed Jwt
       * @param jwk The JWK to verify the JWTs signature with
       * @param verifyProperties The properties to use for verification
       * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
       */
      verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties) {
        const jwk = this.jwksCache.getCachedJwk(jwksUri, decomposedJwt);
        return verifyDecomposedJwtSync(decomposedJwt, jwk, verifyProperties, this.publicKeyCache.transformJwkToKeyObject.bind(this.publicKeyCache));
      }
      /**
       * Verify (asynchronously) a JWT that is signed using RS256 / RS384 / RS512.
       * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
       * in case it is not yet available in the cache.
       *
       * @param jwt The JWT, as string
       * @param props Verification properties
       * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
       */
      async verify(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        return this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
      }
      /**
       * Verify (asynchronously) an already decomposed JWT, that is signed using RS256 / RS384 / RS512.
       *
       * @param decomposedJwt The decomposed Jwt
       * @param jwk The JWK to verify the JWTs signature with
       * @param verifyProperties The properties to use for verification
       * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
       */
      verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties) {
        return verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties, this.jwksCache.getJwk.bind(this.jwksCache), this.publicKeyCache.transformJwkToKeyObject.bind(this.publicKeyCache));
      }
      /**
       * Get the verification parameters to use, by merging the issuer configuration,
       * with the overriding properties that are now provided
       *
       * @param jwt: the JWT that is going to be verified
       * @param verifyProperties: the overriding properties, that override the issuer configuration
       * @returns The merged verification parameters
       */
      getVerifyParameters(jwt, verifyProperties) {
        const decomposedJwt = (0, jwt_js_1.decomposeJwt)(jwt);
        (0, assert_js_1.assertStringArrayContainsString)("Issuer", decomposedJwt.payload.iss, this.expectedIssuers, error_js_1.JwtInvalidIssuerError);
        const issuerConfig = this.getIssuerConfig(decomposedJwt.payload.iss);
        return {
          decomposedJwt,
          jwksUri: issuerConfig.jwksUri,
          verifyProperties: {
            ...issuerConfig,
            ...verifyProperties
          }
        };
      }
      /**
       * Get issuer config with JWKS URI, by adding a default JWKS URI if needed
       *
       * @param config: the issuer config.
       * @returns The config with JWKS URI
       */
      withJwksUri(config) {
        if (config.jwksUri) {
          return config;
        }
        const issuerUri = new url_1.URL(config.issuer);
        return {
          jwksUri: new url_1.URL((0, path_1.join)(issuerUri.pathname, "/.well-known/jwks.json"), config.issuer).href,
          ...config
        };
      }
    };
    exports.JwtRsaVerifierBase = JwtRsaVerifierBase;
    var JwtRsaVerifier = class extends JwtRsaVerifierBase {
      // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
      static create(verifyProperties, additionalProperties) {
        return new this(verifyProperties, additionalProperties?.jwksCache);
      }
    };
    exports.JwtRsaVerifier = JwtRsaVerifier;
    var transformJwkToKeyObject = (jwk) => (0, crypto_1.createPublicKey)({
      key: (0, asn1_js_1.constructPublicKeyInDerFormat)(Buffer.from(jwk.n, "base64"), Buffer.from(jwk.e, "base64")),
      format: "der",
      type: "spki"
    });
    exports.transformJwkToKeyObject = transformJwkToKeyObject;
    var KeyObjectCache = class {
      constructor(jwkToKeyObjectTransformer = exports.transformJwkToKeyObject) {
        this.jwkToKeyObjectTransformer = jwkToKeyObjectTransformer;
        this.publicKeys = /* @__PURE__ */ new Map();
      }
      /**
       * Transform the JWK into an RSA public key in Node.js native key object format.
       * If the transformed JWK is already in the cache, it is returned from the cache instead.
       * The cache keys are: issuer, JWK kid (key id)
       *
       * @param jwk: the JWK
       * @param issuer: the issuer that uses the JWK for signing JWTs
       * @returns the RSA public key in Node.js native key object format
       */
      transformJwkToKeyObject(jwk, issuer) {
        if (!issuer) {
          return this.jwkToKeyObjectTransformer(jwk);
        }
        const cachedPublicKey = this.publicKeys.get(issuer)?.get(jwk.kid);
        if (cachedPublicKey) {
          return cachedPublicKey;
        }
        const publicKey = this.jwkToKeyObjectTransformer(jwk);
        const cachedIssuer = this.publicKeys.get(issuer);
        if (cachedIssuer) {
          cachedIssuer.set(jwk.kid, publicKey);
        } else {
          this.publicKeys.set(issuer, /* @__PURE__ */ new Map([[jwk.kid, publicKey]]));
        }
        return publicKey;
      }
      clearCache(issuer) {
        this.publicKeys.delete(issuer);
      }
    };
    exports.KeyObjectCache = KeyObjectCache;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/cognito-verifier.js
var require_cognito_verifier = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/cognito-verifier.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.CognitoJwtVerifier = void 0;
    var error_js_1 = require_error();
    var jwt_rsa_js_1 = require_jwt_rsa();
    var assert_js_1 = require_assert();
    function validateCognitoJwtFields(payload, options) {
      if (options.groups != null) {
        (0, assert_js_1.assertStringArraysOverlap)("Cognito group", payload["cognito:groups"], options.groups, error_js_1.CognitoJwtInvalidGroupError);
      }
      (0, assert_js_1.assertStringArrayContainsString)("Token use", payload.token_use, ["id", "access"], error_js_1.CognitoJwtInvalidTokenUseError);
      if (options.tokenUse !== null) {
        if (options.tokenUse === void 0) {
          throw new error_js_1.ParameterValidationError("tokenUse must be provided or set to null explicitly");
        }
        (0, assert_js_1.assertStringEquals)("Token use", payload.token_use, options.tokenUse, error_js_1.CognitoJwtInvalidTokenUseError);
      }
      if (options.clientId !== null) {
        if (options.clientId === void 0) {
          throw new error_js_1.ParameterValidationError("clientId must be provided or set to null explicitly");
        }
        if (payload.token_use === "id") {
          (0, assert_js_1.assertStringArrayContainsString)('Client ID ("audience")', payload.aud, options.clientId, error_js_1.CognitoJwtInvalidClientIdError);
        } else {
          (0, assert_js_1.assertStringArrayContainsString)("Client ID", payload.client_id, options.clientId, error_js_1.CognitoJwtInvalidClientIdError);
        }
      }
    }
    var CognitoJwtVerifier = class _CognitoJwtVerifier extends jwt_rsa_js_1.JwtRsaVerifierBase {
      constructor(props, jwksCache) {
        const issuerConfig = Array.isArray(props) ? props.map((p) => ({
          ...p,
          ..._CognitoJwtVerifier.parseUserPoolId(p.userPoolId),
          audience: null
          // checked instead by validateCognitoJwtFields
        })) : {
          ...props,
          ..._CognitoJwtVerifier.parseUserPoolId(props.userPoolId),
          audience: null
          // checked instead by validateCognitoJwtFields
        };
        super(issuerConfig, jwksCache);
      }
      /**
       * Parse a User Pool ID, to extract the issuer and JWKS URI
       *
       * @param userPoolId The User Pool ID
       * @returns The issuer and JWKS URI for the User Pool
       */
      static parseUserPoolId(userPoolId) {
        const match = userPoolId.match(/^(?<region>(\w+-)?\w+-\w+-\d)+_\w+$/);
        if (!match) {
          throw new error_js_1.ParameterValidationError(`Invalid Cognito User Pool ID: ${userPoolId}`);
        }
        const region = match.groups.region;
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        return {
          issuer,
          jwksUri: `${issuer}/.well-known/jwks.json`
        };
      }
      // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
      static create(verifyProperties, additionalProperties) {
        return new this(verifyProperties, additionalProperties?.jwksCache);
      }
      /**
       * Verify (synchronously) a JWT that is signed by Amazon Cognito.
       *
       * @param jwt The JWT, as string
       * @param props Verification properties
       * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
       */
      verifySync(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
        try {
          validateCognitoJwtFields(decomposedJwt.payload, verifyProperties);
        } catch (err) {
          if (verifyProperties.includeRawJwtInErrors && err instanceof error_js_1.JwtInvalidClaimError) {
            throw err.withRawJwt(decomposedJwt);
          }
          throw err;
        }
        return decomposedJwt.payload;
      }
      /**
       * Verify (asynchronously) a JWT that is signed by Amazon Cognito.
       * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
       * in case it is not yet available in the cache.
       *
       * @param jwt The JWT, as string
       * @param props Verification properties
       * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
       */
      async verify(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        await this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
        try {
          validateCognitoJwtFields(decomposedJwt.payload, verifyProperties);
        } catch (err) {
          if (verifyProperties.includeRawJwtInErrors && err instanceof error_js_1.JwtInvalidClaimError) {
            throw err.withRawJwt(decomposedJwt);
          }
          throw err;
        }
        return decomposedJwt.payload;
      }
      /**
       * This method loads a JWKS that you provide, into the JWKS cache, so that it is
       * available for JWT verification. Use this method to speed up the first JWT verification
       * (when the JWKS would otherwise have to be downloaded from the JWKS uri), or to provide the JWKS
       * in case the JwtVerifier does not have internet access to download the JWKS
       *
       * @param jwks The JWKS
       * @param userPoolId The userPoolId for which you want to cache the JWKS
       *  Supply this field, if you instantiated the CognitoJwtVerifier with multiple userPoolIds
       * @returns void
       */
      cacheJwks(...[jwks, userPoolId]) {
        let issuer;
        if (userPoolId !== void 0) {
          issuer = _CognitoJwtVerifier.parseUserPoolId(userPoolId).issuer;
        } else if (this.expectedIssuers.length > 1) {
          throw new error_js_1.ParameterValidationError("userPoolId must be provided");
        }
        const issuerConfig = this.getIssuerConfig(issuer);
        super.cacheJwks(jwks, issuerConfig.issuer);
      }
    };
    exports.CognitoJwtVerifier = CognitoJwtVerifier;
  }
});

// ../../node_modules/aws-jwt-verify/dist/cjs/index.js
var require_cjs = __commonJS({
  "../../node_modules/aws-jwt-verify/dist/cjs/index.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.CognitoJwtVerifier = exports.JwtRsaVerifier = void 0;
    var jwt_rsa_js_1 = require_jwt_rsa();
    Object.defineProperty(exports, "JwtRsaVerifier", { enumerable: true, get: function() {
      return jwt_rsa_js_1.JwtRsaVerifier;
    } });
    var cognito_verifier_js_1 = require_cognito_verifier();
    Object.defineProperty(exports, "CognitoJwtVerifier", { enumerable: true, get: function() {
      return cognito_verifier_js_1.CognitoJwtVerifier;
    } });
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/bind.js
var require_bind = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/bind.js"(exports, module2) {
    "use strict";
    module2.exports = function bind(fn, thisArg) {
      return function wrap() {
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; i++) {
          args[i] = arguments[i];
        }
        return fn.apply(thisArg, args);
      };
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/utils.js
var require_utils = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/utils.js"(exports, module2) {
    "use strict";
    var bind = require_bind();
    var toString = Object.prototype.toString;
    function isArray(val) {
      return Array.isArray(val);
    }
    function isUndefined(val) {
      return typeof val === "undefined";
    }
    function isBuffer(val) {
      return val !== null && !isUndefined(val) && val.constructor !== null && !isUndefined(val.constructor) && typeof val.constructor.isBuffer === "function" && val.constructor.isBuffer(val);
    }
    function isArrayBuffer(val) {
      return toString.call(val) === "[object ArrayBuffer]";
    }
    function isFormData(val) {
      return toString.call(val) === "[object FormData]";
    }
    function isArrayBufferView(val) {
      var result;
      if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView) {
        result = ArrayBuffer.isView(val);
      } else {
        result = val && val.buffer && isArrayBuffer(val.buffer);
      }
      return result;
    }
    function isString(val) {
      return typeof val === "string";
    }
    function isNumber(val) {
      return typeof val === "number";
    }
    function isObject(val) {
      return val !== null && typeof val === "object";
    }
    function isPlainObject(val) {
      if (toString.call(val) !== "[object Object]") {
        return false;
      }
      var prototype = Object.getPrototypeOf(val);
      return prototype === null || prototype === Object.prototype;
    }
    function isDate(val) {
      return toString.call(val) === "[object Date]";
    }
    function isFile(val) {
      return toString.call(val) === "[object File]";
    }
    function isBlob(val) {
      return toString.call(val) === "[object Blob]";
    }
    function isFunction(val) {
      return toString.call(val) === "[object Function]";
    }
    function isStream(val) {
      return isObject(val) && isFunction(val.pipe);
    }
    function isURLSearchParams(val) {
      return toString.call(val) === "[object URLSearchParams]";
    }
    function trim(str) {
      return str.trim ? str.trim() : str.replace(/^\s+|\s+$/g, "");
    }
    function isStandardBrowserEnv() {
      if (typeof navigator !== "undefined" && (navigator.product === "ReactNative" || navigator.product === "NativeScript" || navigator.product === "NS")) {
        return false;
      }
      return typeof window !== "undefined" && typeof document !== "undefined";
    }
    function forEach(obj, fn) {
      if (obj === null || typeof obj === "undefined") {
        return;
      }
      if (typeof obj !== "object") {
        obj = [obj];
      }
      if (isArray(obj)) {
        for (var i = 0, l = obj.length; i < l; i++) {
          fn.call(null, obj[i], i, obj);
        }
      } else {
        for (var key in obj) {
          if (Object.prototype.hasOwnProperty.call(obj, key)) {
            fn.call(null, obj[key], key, obj);
          }
        }
      }
    }
    function merge() {
      var result = {};
      function assignValue(val, key) {
        if (isPlainObject(result[key]) && isPlainObject(val)) {
          result[key] = merge(result[key], val);
        } else if (isPlainObject(val)) {
          result[key] = merge({}, val);
        } else if (isArray(val)) {
          result[key] = val.slice();
        } else {
          result[key] = val;
        }
      }
      for (var i = 0, l = arguments.length; i < l; i++) {
        forEach(arguments[i], assignValue);
      }
      return result;
    }
    function extend(a, b, thisArg) {
      forEach(b, function assignValue(val, key) {
        if (thisArg && typeof val === "function") {
          a[key] = bind(val, thisArg);
        } else {
          a[key] = val;
        }
      });
      return a;
    }
    function stripBOM(content) {
      if (content.charCodeAt(0) === 65279) {
        content = content.slice(1);
      }
      return content;
    }
    module2.exports = {
      isArray,
      isArrayBuffer,
      isBuffer,
      isFormData,
      isArrayBufferView,
      isString,
      isNumber,
      isObject,
      isPlainObject,
      isUndefined,
      isDate,
      isFile,
      isBlob,
      isFunction,
      isStream,
      isURLSearchParams,
      isStandardBrowserEnv,
      forEach,
      merge,
      extend,
      trim,
      stripBOM
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/buildURL.js
var require_buildURL = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/buildURL.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    function encode(val) {
      return encodeURIComponent(val).replace(/%3A/gi, ":").replace(/%24/g, "$").replace(/%2C/gi, ",").replace(/%20/g, "+").replace(/%5B/gi, "[").replace(/%5D/gi, "]");
    }
    module2.exports = function buildURL(url, params, paramsSerializer) {
      if (!params) {
        return url;
      }
      var serializedParams;
      if (paramsSerializer) {
        serializedParams = paramsSerializer(params);
      } else if (utils.isURLSearchParams(params)) {
        serializedParams = params.toString();
      } else {
        var parts = [];
        utils.forEach(params, function serialize(val, key) {
          if (val === null || typeof val === "undefined") {
            return;
          }
          if (utils.isArray(val)) {
            key = key + "[]";
          } else {
            val = [val];
          }
          utils.forEach(val, function parseValue(v) {
            if (utils.isDate(v)) {
              v = v.toISOString();
            } else if (utils.isObject(v)) {
              v = JSON.stringify(v);
            }
            parts.push(encode(key) + "=" + encode(v));
          });
        });
        serializedParams = parts.join("&");
      }
      if (serializedParams) {
        var hashmarkIndex = url.indexOf("#");
        if (hashmarkIndex !== -1) {
          url = url.slice(0, hashmarkIndex);
        }
        url += (url.indexOf("?") === -1 ? "?" : "&") + serializedParams;
      }
      return url;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/InterceptorManager.js
var require_InterceptorManager = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/InterceptorManager.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    function InterceptorManager() {
      this.handlers = [];
    }
    InterceptorManager.prototype.use = function use(fulfilled, rejected, options) {
      this.handlers.push({
        fulfilled,
        rejected,
        synchronous: options ? options.synchronous : false,
        runWhen: options ? options.runWhen : null
      });
      return this.handlers.length - 1;
    };
    InterceptorManager.prototype.eject = function eject(id) {
      if (this.handlers[id]) {
        this.handlers[id] = null;
      }
    };
    InterceptorManager.prototype.forEach = function forEach(fn) {
      utils.forEach(this.handlers, function forEachHandler(h) {
        if (h !== null) {
          fn(h);
        }
      });
    };
    module2.exports = InterceptorManager;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/normalizeHeaderName.js
var require_normalizeHeaderName = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/normalizeHeaderName.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    module2.exports = function normalizeHeaderName(headers, normalizedName) {
      utils.forEach(headers, function processHeader(value, name) {
        if (name !== normalizedName && name.toUpperCase() === normalizedName.toUpperCase()) {
          headers[normalizedName] = value;
          delete headers[name];
        }
      });
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/enhanceError.js
var require_enhanceError = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/enhanceError.js"(exports, module2) {
    "use strict";
    module2.exports = function enhanceError(error, config, code, request, response) {
      error.config = config;
      if (code) {
        error.code = code;
      }
      error.request = request;
      error.response = response;
      error.isAxiosError = true;
      error.toJSON = function toJSON() {
        return {
          // Standard
          message: this.message,
          name: this.name,
          // Microsoft
          description: this.description,
          number: this.number,
          // Mozilla
          fileName: this.fileName,
          lineNumber: this.lineNumber,
          columnNumber: this.columnNumber,
          stack: this.stack,
          // Axios
          config: this.config,
          code: this.code,
          status: this.response && this.response.status ? this.response.status : null
        };
      };
      return error;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/createError.js
var require_createError = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/createError.js"(exports, module2) {
    "use strict";
    var enhanceError = require_enhanceError();
    module2.exports = function createError(message, config, code, request, response) {
      var error = new Error(message);
      return enhanceError(error, config, code, request, response);
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/settle.js
var require_settle = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/settle.js"(exports, module2) {
    "use strict";
    var createError = require_createError();
    module2.exports = function settle(resolve, reject, response) {
      var validateStatus = response.config.validateStatus;
      if (!response.status || !validateStatus || validateStatus(response.status)) {
        resolve(response);
      } else {
        reject(createError(
          "Request failed with status code " + response.status,
          response.config,
          null,
          response.request,
          response
        ));
      }
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/cookies.js
var require_cookies = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/cookies.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    module2.exports = utils.isStandardBrowserEnv() ? (
      // Standard browser envs support document.cookie
      function standardBrowserEnv() {
        return {
          write: function write(name, value, expires, path, domain, secure) {
            var cookie = [];
            cookie.push(name + "=" + encodeURIComponent(value));
            if (utils.isNumber(expires)) {
              cookie.push("expires=" + new Date(expires).toGMTString());
            }
            if (utils.isString(path)) {
              cookie.push("path=" + path);
            }
            if (utils.isString(domain)) {
              cookie.push("domain=" + domain);
            }
            if (secure === true) {
              cookie.push("secure");
            }
            document.cookie = cookie.join("; ");
          },
          read: function read(name) {
            var match = document.cookie.match(new RegExp("(^|;\\s*)(" + name + ")=([^;]*)"));
            return match ? decodeURIComponent(match[3]) : null;
          },
          remove: function remove(name) {
            this.write(name, "", Date.now() - 864e5);
          }
        };
      }()
    ) : (
      // Non standard browser env (web workers, react-native) lack needed support.
      function nonStandardBrowserEnv() {
        return {
          write: function write() {
          },
          read: function read() {
            return null;
          },
          remove: function remove() {
          }
        };
      }()
    );
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/isAbsoluteURL.js
var require_isAbsoluteURL = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/isAbsoluteURL.js"(exports, module2) {
    "use strict";
    module2.exports = function isAbsoluteURL(url) {
      return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(url);
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/combineURLs.js
var require_combineURLs = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/combineURLs.js"(exports, module2) {
    "use strict";
    module2.exports = function combineURLs(baseURL, relativeURL) {
      return relativeURL ? baseURL.replace(/\/+$/, "") + "/" + relativeURL.replace(/^\/+/, "") : baseURL;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/buildFullPath.js
var require_buildFullPath = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/buildFullPath.js"(exports, module2) {
    "use strict";
    var isAbsoluteURL = require_isAbsoluteURL();
    var combineURLs = require_combineURLs();
    module2.exports = function buildFullPath(baseURL, requestedURL) {
      if (baseURL && !isAbsoluteURL(requestedURL)) {
        return combineURLs(baseURL, requestedURL);
      }
      return requestedURL;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/parseHeaders.js
var require_parseHeaders = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/parseHeaders.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var ignoreDuplicateOf = [
      "age",
      "authorization",
      "content-length",
      "content-type",
      "etag",
      "expires",
      "from",
      "host",
      "if-modified-since",
      "if-unmodified-since",
      "last-modified",
      "location",
      "max-forwards",
      "proxy-authorization",
      "referer",
      "retry-after",
      "user-agent"
    ];
    module2.exports = function parseHeaders(headers) {
      var parsed = {};
      var key;
      var val;
      var i;
      if (!headers) {
        return parsed;
      }
      utils.forEach(headers.split("\n"), function parser(line) {
        i = line.indexOf(":");
        key = utils.trim(line.substr(0, i)).toLowerCase();
        val = utils.trim(line.substr(i + 1));
        if (key) {
          if (parsed[key] && ignoreDuplicateOf.indexOf(key) >= 0) {
            return;
          }
          if (key === "set-cookie") {
            parsed[key] = (parsed[key] ? parsed[key] : []).concat([val]);
          } else {
            parsed[key] = parsed[key] ? parsed[key] + ", " + val : val;
          }
        }
      });
      return parsed;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/isURLSameOrigin.js
var require_isURLSameOrigin = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/isURLSameOrigin.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    module2.exports = utils.isStandardBrowserEnv() ? (
      // Standard browser envs have full support of the APIs needed to test
      // whether the request URL is of the same origin as current location.
      function standardBrowserEnv() {
        var msie = /(msie|trident)/i.test(navigator.userAgent);
        var urlParsingNode = document.createElement("a");
        var originURL;
        function resolveURL(url) {
          var href = url;
          if (msie) {
            urlParsingNode.setAttribute("href", href);
            href = urlParsingNode.href;
          }
          urlParsingNode.setAttribute("href", href);
          return {
            href: urlParsingNode.href,
            protocol: urlParsingNode.protocol ? urlParsingNode.protocol.replace(/:$/, "") : "",
            host: urlParsingNode.host,
            search: urlParsingNode.search ? urlParsingNode.search.replace(/^\?/, "") : "",
            hash: urlParsingNode.hash ? urlParsingNode.hash.replace(/^#/, "") : "",
            hostname: urlParsingNode.hostname,
            port: urlParsingNode.port,
            pathname: urlParsingNode.pathname.charAt(0) === "/" ? urlParsingNode.pathname : "/" + urlParsingNode.pathname
          };
        }
        originURL = resolveURL(window.location.href);
        return function isURLSameOrigin(requestURL) {
          var parsed = utils.isString(requestURL) ? resolveURL(requestURL) : requestURL;
          return parsed.protocol === originURL.protocol && parsed.host === originURL.host;
        };
      }()
    ) : (
      // Non standard browser envs (web workers, react-native) lack needed support.
      function nonStandardBrowserEnv() {
        return function isURLSameOrigin() {
          return true;
        };
      }()
    );
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/cancel/Cancel.js
var require_Cancel = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/cancel/Cancel.js"(exports, module2) {
    "use strict";
    function Cancel(message) {
      this.message = message;
    }
    Cancel.prototype.toString = function toString() {
      return "Cancel" + (this.message ? ": " + this.message : "");
    };
    Cancel.prototype.__CANCEL__ = true;
    module2.exports = Cancel;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/adapters/xhr.js
var require_xhr = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/adapters/xhr.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var settle = require_settle();
    var cookies = require_cookies();
    var buildURL = require_buildURL();
    var buildFullPath = require_buildFullPath();
    var parseHeaders = require_parseHeaders();
    var isURLSameOrigin = require_isURLSameOrigin();
    var createError = require_createError();
    var defaults = require_defaults();
    var Cancel = require_Cancel();
    module2.exports = function xhrAdapter(config) {
      return new Promise(function dispatchXhrRequest(resolve, reject) {
        var requestData = config.data;
        var requestHeaders = config.headers;
        var responseType = config.responseType;
        var onCanceled;
        function done() {
          if (config.cancelToken) {
            config.cancelToken.unsubscribe(onCanceled);
          }
          if (config.signal) {
            config.signal.removeEventListener("abort", onCanceled);
          }
        }
        if (utils.isFormData(requestData)) {
          delete requestHeaders["Content-Type"];
        }
        var request = new XMLHttpRequest();
        if (config.auth) {
          var username = config.auth.username || "";
          var password = config.auth.password ? unescape(encodeURIComponent(config.auth.password)) : "";
          requestHeaders.Authorization = "Basic " + btoa(username + ":" + password);
        }
        var fullPath = buildFullPath(config.baseURL, config.url);
        request.open(config.method.toUpperCase(), buildURL(fullPath, config.params, config.paramsSerializer), true);
        request.timeout = config.timeout;
        function onloadend() {
          if (!request) {
            return;
          }
          var responseHeaders = "getAllResponseHeaders" in request ? parseHeaders(request.getAllResponseHeaders()) : null;
          var responseData = !responseType || responseType === "text" || responseType === "json" ? request.responseText : request.response;
          var response = {
            data: responseData,
            status: request.status,
            statusText: request.statusText,
            headers: responseHeaders,
            config,
            request
          };
          settle(function _resolve(value) {
            resolve(value);
            done();
          }, function _reject(err) {
            reject(err);
            done();
          }, response);
          request = null;
        }
        if ("onloadend" in request) {
          request.onloadend = onloadend;
        } else {
          request.onreadystatechange = function handleLoad() {
            if (!request || request.readyState !== 4) {
              return;
            }
            if (request.status === 0 && !(request.responseURL && request.responseURL.indexOf("file:") === 0)) {
              return;
            }
            setTimeout(onloadend);
          };
        }
        request.onabort = function handleAbort() {
          if (!request) {
            return;
          }
          reject(createError("Request aborted", config, "ECONNABORTED", request));
          request = null;
        };
        request.onerror = function handleError() {
          reject(createError("Network Error", config, null, request));
          request = null;
        };
        request.ontimeout = function handleTimeout() {
          var timeoutErrorMessage = config.timeout ? "timeout of " + config.timeout + "ms exceeded" : "timeout exceeded";
          var transitional = config.transitional || defaults.transitional;
          if (config.timeoutErrorMessage) {
            timeoutErrorMessage = config.timeoutErrorMessage;
          }
          reject(createError(
            timeoutErrorMessage,
            config,
            transitional.clarifyTimeoutError ? "ETIMEDOUT" : "ECONNABORTED",
            request
          ));
          request = null;
        };
        if (utils.isStandardBrowserEnv()) {
          var xsrfValue = (config.withCredentials || isURLSameOrigin(fullPath)) && config.xsrfCookieName ? cookies.read(config.xsrfCookieName) : void 0;
          if (xsrfValue) {
            requestHeaders[config.xsrfHeaderName] = xsrfValue;
          }
        }
        if ("setRequestHeader" in request) {
          utils.forEach(requestHeaders, function setRequestHeader(val, key) {
            if (typeof requestData === "undefined" && key.toLowerCase() === "content-type") {
              delete requestHeaders[key];
            } else {
              request.setRequestHeader(key, val);
            }
          });
        }
        if (!utils.isUndefined(config.withCredentials)) {
          request.withCredentials = !!config.withCredentials;
        }
        if (responseType && responseType !== "json") {
          request.responseType = config.responseType;
        }
        if (typeof config.onDownloadProgress === "function") {
          request.addEventListener("progress", config.onDownloadProgress);
        }
        if (typeof config.onUploadProgress === "function" && request.upload) {
          request.upload.addEventListener("progress", config.onUploadProgress);
        }
        if (config.cancelToken || config.signal) {
          onCanceled = function(cancel) {
            if (!request) {
              return;
            }
            reject(!cancel || cancel && cancel.type ? new Cancel("canceled") : cancel);
            request.abort();
            request = null;
          };
          config.cancelToken && config.cancelToken.subscribe(onCanceled);
          if (config.signal) {
            config.signal.aborted ? onCanceled() : config.signal.addEventListener("abort", onCanceled);
          }
        }
        if (!requestData) {
          requestData = null;
        }
        request.send(requestData);
      });
    };
  }
});

// ../../node_modules/ms/index.js
var require_ms = __commonJS({
  "../../node_modules/ms/index.js"(exports, module2) {
    var s = 1e3;
    var m = s * 60;
    var h = m * 60;
    var d = h * 24;
    var w = d * 7;
    var y = d * 365.25;
    module2.exports = function(val, options) {
      options = options || {};
      var type = typeof val;
      if (type === "string" && val.length > 0) {
        return parse(val);
      } else if (type === "number" && isFinite(val)) {
        return options.long ? fmtLong(val) : fmtShort(val);
      }
      throw new Error(
        "val is not a non-empty string or a valid number. val=" + JSON.stringify(val)
      );
    };
    function parse(str) {
      str = String(str);
      if (str.length > 100) {
        return;
      }
      var match = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
        str
      );
      if (!match) {
        return;
      }
      var n = parseFloat(match[1]);
      var type = (match[2] || "ms").toLowerCase();
      switch (type) {
        case "years":
        case "year":
        case "yrs":
        case "yr":
        case "y":
          return n * y;
        case "weeks":
        case "week":
        case "w":
          return n * w;
        case "days":
        case "day":
        case "d":
          return n * d;
        case "hours":
        case "hour":
        case "hrs":
        case "hr":
        case "h":
          return n * h;
        case "minutes":
        case "minute":
        case "mins":
        case "min":
        case "m":
          return n * m;
        case "seconds":
        case "second":
        case "secs":
        case "sec":
        case "s":
          return n * s;
        case "milliseconds":
        case "millisecond":
        case "msecs":
        case "msec":
        case "ms":
          return n;
        default:
          return void 0;
      }
    }
    function fmtShort(ms) {
      var msAbs = Math.abs(ms);
      if (msAbs >= d) {
        return Math.round(ms / d) + "d";
      }
      if (msAbs >= h) {
        return Math.round(ms / h) + "h";
      }
      if (msAbs >= m) {
        return Math.round(ms / m) + "m";
      }
      if (msAbs >= s) {
        return Math.round(ms / s) + "s";
      }
      return ms + "ms";
    }
    function fmtLong(ms) {
      var msAbs = Math.abs(ms);
      if (msAbs >= d) {
        return plural(ms, msAbs, d, "day");
      }
      if (msAbs >= h) {
        return plural(ms, msAbs, h, "hour");
      }
      if (msAbs >= m) {
        return plural(ms, msAbs, m, "minute");
      }
      if (msAbs >= s) {
        return plural(ms, msAbs, s, "second");
      }
      return ms + " ms";
    }
    function plural(ms, msAbs, n, name) {
      var isPlural = msAbs >= n * 1.5;
      return Math.round(ms / n) + " " + name + (isPlural ? "s" : "");
    }
  }
});

// ../../node_modules/debug/src/common.js
var require_common = __commonJS({
  "../../node_modules/debug/src/common.js"(exports, module2) {
    function setup(env) {
      createDebug.debug = createDebug;
      createDebug.default = createDebug;
      createDebug.coerce = coerce;
      createDebug.disable = disable;
      createDebug.enable = enable;
      createDebug.enabled = enabled;
      createDebug.humanize = require_ms();
      createDebug.destroy = destroy;
      Object.keys(env).forEach((key) => {
        createDebug[key] = env[key];
      });
      createDebug.names = [];
      createDebug.skips = [];
      createDebug.formatters = {};
      function selectColor(namespace) {
        let hash = 0;
        for (let i = 0; i < namespace.length; i++) {
          hash = (hash << 5) - hash + namespace.charCodeAt(i);
          hash |= 0;
        }
        return createDebug.colors[Math.abs(hash) % createDebug.colors.length];
      }
      createDebug.selectColor = selectColor;
      function createDebug(namespace) {
        let prevTime;
        let enableOverride = null;
        let namespacesCache;
        let enabledCache;
        function debug(...args) {
          if (!debug.enabled) {
            return;
          }
          const self = debug;
          const curr = Number(/* @__PURE__ */ new Date());
          const ms = curr - (prevTime || curr);
          self.diff = ms;
          self.prev = prevTime;
          self.curr = curr;
          prevTime = curr;
          args[0] = createDebug.coerce(args[0]);
          if (typeof args[0] !== "string") {
            args.unshift("%O");
          }
          let index = 0;
          args[0] = args[0].replace(/%([a-zA-Z%])/g, (match, format) => {
            if (match === "%%") {
              return "%";
            }
            index++;
            const formatter = createDebug.formatters[format];
            if (typeof formatter === "function") {
              const val = args[index];
              match = formatter.call(self, val);
              args.splice(index, 1);
              index--;
            }
            return match;
          });
          createDebug.formatArgs.call(self, args);
          const logFn = self.log || createDebug.log;
          logFn.apply(self, args);
        }
        debug.namespace = namespace;
        debug.useColors = createDebug.useColors();
        debug.color = createDebug.selectColor(namespace);
        debug.extend = extend;
        debug.destroy = createDebug.destroy;
        Object.defineProperty(debug, "enabled", {
          enumerable: true,
          configurable: false,
          get: () => {
            if (enableOverride !== null) {
              return enableOverride;
            }
            if (namespacesCache !== createDebug.namespaces) {
              namespacesCache = createDebug.namespaces;
              enabledCache = createDebug.enabled(namespace);
            }
            return enabledCache;
          },
          set: (v) => {
            enableOverride = v;
          }
        });
        if (typeof createDebug.init === "function") {
          createDebug.init(debug);
        }
        return debug;
      }
      function extend(namespace, delimiter) {
        const newDebug = createDebug(this.namespace + (typeof delimiter === "undefined" ? ":" : delimiter) + namespace);
        newDebug.log = this.log;
        return newDebug;
      }
      function enable(namespaces) {
        createDebug.save(namespaces);
        createDebug.namespaces = namespaces;
        createDebug.names = [];
        createDebug.skips = [];
        let i;
        const split = (typeof namespaces === "string" ? namespaces : "").split(/[\s,]+/);
        const len = split.length;
        for (i = 0; i < len; i++) {
          if (!split[i]) {
            continue;
          }
          namespaces = split[i].replace(/\*/g, ".*?");
          if (namespaces[0] === "-") {
            createDebug.skips.push(new RegExp("^" + namespaces.slice(1) + "$"));
          } else {
            createDebug.names.push(new RegExp("^" + namespaces + "$"));
          }
        }
      }
      function disable() {
        const namespaces = [
          ...createDebug.names.map(toNamespace),
          ...createDebug.skips.map(toNamespace).map((namespace) => "-" + namespace)
        ].join(",");
        createDebug.enable("");
        return namespaces;
      }
      function enabled(name) {
        if (name[name.length - 1] === "*") {
          return true;
        }
        let i;
        let len;
        for (i = 0, len = createDebug.skips.length; i < len; i++) {
          if (createDebug.skips[i].test(name)) {
            return false;
          }
        }
        for (i = 0, len = createDebug.names.length; i < len; i++) {
          if (createDebug.names[i].test(name)) {
            return true;
          }
        }
        return false;
      }
      function toNamespace(regexp) {
        return regexp.toString().substring(2, regexp.toString().length - 2).replace(/\.\*\?$/, "*");
      }
      function coerce(val) {
        if (val instanceof Error) {
          return val.stack || val.message;
        }
        return val;
      }
      function destroy() {
        console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.");
      }
      createDebug.enable(createDebug.load());
      return createDebug;
    }
    module2.exports = setup;
  }
});

// ../../node_modules/debug/src/browser.js
var require_browser = __commonJS({
  "../../node_modules/debug/src/browser.js"(exports, module2) {
    exports.formatArgs = formatArgs;
    exports.save = save;
    exports.load = load;
    exports.useColors = useColors;
    exports.storage = localstorage();
    exports.destroy = (() => {
      let warned = false;
      return () => {
        if (!warned) {
          warned = true;
          console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.");
        }
      };
    })();
    exports.colors = [
      "#0000CC",
      "#0000FF",
      "#0033CC",
      "#0033FF",
      "#0066CC",
      "#0066FF",
      "#0099CC",
      "#0099FF",
      "#00CC00",
      "#00CC33",
      "#00CC66",
      "#00CC99",
      "#00CCCC",
      "#00CCFF",
      "#3300CC",
      "#3300FF",
      "#3333CC",
      "#3333FF",
      "#3366CC",
      "#3366FF",
      "#3399CC",
      "#3399FF",
      "#33CC00",
      "#33CC33",
      "#33CC66",
      "#33CC99",
      "#33CCCC",
      "#33CCFF",
      "#6600CC",
      "#6600FF",
      "#6633CC",
      "#6633FF",
      "#66CC00",
      "#66CC33",
      "#9900CC",
      "#9900FF",
      "#9933CC",
      "#9933FF",
      "#99CC00",
      "#99CC33",
      "#CC0000",
      "#CC0033",
      "#CC0066",
      "#CC0099",
      "#CC00CC",
      "#CC00FF",
      "#CC3300",
      "#CC3333",
      "#CC3366",
      "#CC3399",
      "#CC33CC",
      "#CC33FF",
      "#CC6600",
      "#CC6633",
      "#CC9900",
      "#CC9933",
      "#CCCC00",
      "#CCCC33",
      "#FF0000",
      "#FF0033",
      "#FF0066",
      "#FF0099",
      "#FF00CC",
      "#FF00FF",
      "#FF3300",
      "#FF3333",
      "#FF3366",
      "#FF3399",
      "#FF33CC",
      "#FF33FF",
      "#FF6600",
      "#FF6633",
      "#FF9900",
      "#FF9933",
      "#FFCC00",
      "#FFCC33"
    ];
    function useColors() {
      if (typeof window !== "undefined" && window.process && (window.process.type === "renderer" || window.process.__nwjs)) {
        return true;
      }
      if (typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/)) {
        return false;
      }
      return typeof document !== "undefined" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || // Is firebug? http://stackoverflow.com/a/398120/376773
      typeof window !== "undefined" && window.console && (window.console.firebug || window.console.exception && window.console.table) || // Is firefox >= v31?
      // https://developer.mozilla.org/en-US/docs/Tools/Web_Console#Styling_messages
      typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/) && parseInt(RegExp.$1, 10) >= 31 || // Double check webkit in userAgent just in case we are in a worker
      typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
    }
    function formatArgs(args) {
      args[0] = (this.useColors ? "%c" : "") + this.namespace + (this.useColors ? " %c" : " ") + args[0] + (this.useColors ? "%c " : " ") + "+" + module2.exports.humanize(this.diff);
      if (!this.useColors) {
        return;
      }
      const c = "color: " + this.color;
      args.splice(1, 0, c, "color: inherit");
      let index = 0;
      let lastC = 0;
      args[0].replace(/%[a-zA-Z%]/g, (match) => {
        if (match === "%%") {
          return;
        }
        index++;
        if (match === "%c") {
          lastC = index;
        }
      });
      args.splice(lastC, 0, c);
    }
    exports.log = console.debug || console.log || (() => {
    });
    function save(namespaces) {
      try {
        if (namespaces) {
          exports.storage.setItem("debug", namespaces);
        } else {
          exports.storage.removeItem("debug");
        }
      } catch (error) {
      }
    }
    function load() {
      let r;
      try {
        r = exports.storage.getItem("debug");
      } catch (error) {
      }
      if (!r && typeof process !== "undefined" && "env" in process) {
        r = process.env.DEBUG;
      }
      return r;
    }
    function localstorage() {
      try {
        return localStorage;
      } catch (error) {
      }
    }
    module2.exports = require_common()(exports);
    var { formatters } = module2.exports;
    formatters.j = function(v) {
      try {
        return JSON.stringify(v);
      } catch (error) {
        return "[UnexpectedJSONParseError]: " + error.message;
      }
    };
  }
});

// ../../node_modules/has-flag/index.js
var require_has_flag = __commonJS({
  "../../node_modules/has-flag/index.js"(exports, module2) {
    "use strict";
    module2.exports = (flag, argv = process.argv) => {
      const prefix = flag.startsWith("-") ? "" : flag.length === 1 ? "-" : "--";
      const position = argv.indexOf(prefix + flag);
      const terminatorPosition = argv.indexOf("--");
      return position !== -1 && (terminatorPosition === -1 || position < terminatorPosition);
    };
  }
});

// ../../node_modules/supports-color/index.js
var require_supports_color = __commonJS({
  "../../node_modules/supports-color/index.js"(exports, module2) {
    "use strict";
    var os = require("os");
    var tty = require("tty");
    var hasFlag = require_has_flag();
    var { env } = process;
    var forceColor;
    if (hasFlag("no-color") || hasFlag("no-colors") || hasFlag("color=false") || hasFlag("color=never")) {
      forceColor = 0;
    } else if (hasFlag("color") || hasFlag("colors") || hasFlag("color=true") || hasFlag("color=always")) {
      forceColor = 1;
    }
    if ("FORCE_COLOR" in env) {
      if (env.FORCE_COLOR === "true") {
        forceColor = 1;
      } else if (env.FORCE_COLOR === "false") {
        forceColor = 0;
      } else {
        forceColor = env.FORCE_COLOR.length === 0 ? 1 : Math.min(parseInt(env.FORCE_COLOR, 10), 3);
      }
    }
    function translateLevel(level) {
      if (level === 0) {
        return false;
      }
      return {
        level,
        hasBasic: true,
        has256: level >= 2,
        has16m: level >= 3
      };
    }
    function supportsColor(haveStream, streamIsTTY) {
      if (forceColor === 0) {
        return 0;
      }
      if (hasFlag("color=16m") || hasFlag("color=full") || hasFlag("color=truecolor")) {
        return 3;
      }
      if (hasFlag("color=256")) {
        return 2;
      }
      if (haveStream && !streamIsTTY && forceColor === void 0) {
        return 0;
      }
      const min = forceColor || 0;
      if (env.TERM === "dumb") {
        return min;
      }
      if (process.platform === "win32") {
        const osRelease = os.release().split(".");
        if (Number(osRelease[0]) >= 10 && Number(osRelease[2]) >= 10586) {
          return Number(osRelease[2]) >= 14931 ? 3 : 2;
        }
        return 1;
      }
      if ("CI" in env) {
        if (["TRAVIS", "CIRCLECI", "APPVEYOR", "GITLAB_CI", "GITHUB_ACTIONS", "BUILDKITE"].some((sign) => sign in env) || env.CI_NAME === "codeship") {
          return 1;
        }
        return min;
      }
      if ("TEAMCITY_VERSION" in env) {
        return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env.TEAMCITY_VERSION) ? 1 : 0;
      }
      if (env.COLORTERM === "truecolor") {
        return 3;
      }
      if ("TERM_PROGRAM" in env) {
        const version = parseInt((env.TERM_PROGRAM_VERSION || "").split(".")[0], 10);
        switch (env.TERM_PROGRAM) {
          case "iTerm.app":
            return version >= 3 ? 3 : 2;
          case "Apple_Terminal":
            return 2;
        }
      }
      if (/-256(color)?$/i.test(env.TERM)) {
        return 2;
      }
      if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env.TERM)) {
        return 1;
      }
      if ("COLORTERM" in env) {
        return 1;
      }
      return min;
    }
    function getSupportLevel(stream) {
      const level = supportsColor(stream, stream && stream.isTTY);
      return translateLevel(level);
    }
    module2.exports = {
      supportsColor: getSupportLevel,
      stdout: translateLevel(supportsColor(true, tty.isatty(1))),
      stderr: translateLevel(supportsColor(true, tty.isatty(2)))
    };
  }
});

// ../../node_modules/debug/src/node.js
var require_node = __commonJS({
  "../../node_modules/debug/src/node.js"(exports, module2) {
    var tty = require("tty");
    var util = require("util");
    exports.init = init;
    exports.log = log;
    exports.formatArgs = formatArgs;
    exports.save = save;
    exports.load = load;
    exports.useColors = useColors;
    exports.destroy = util.deprecate(
      () => {
      },
      "Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`."
    );
    exports.colors = [6, 2, 3, 4, 5, 1];
    try {
      const supportsColor = require_supports_color();
      if (supportsColor && (supportsColor.stderr || supportsColor).level >= 2) {
        exports.colors = [
          20,
          21,
          26,
          27,
          32,
          33,
          38,
          39,
          40,
          41,
          42,
          43,
          44,
          45,
          56,
          57,
          62,
          63,
          68,
          69,
          74,
          75,
          76,
          77,
          78,
          79,
          80,
          81,
          92,
          93,
          98,
          99,
          112,
          113,
          128,
          129,
          134,
          135,
          148,
          149,
          160,
          161,
          162,
          163,
          164,
          165,
          166,
          167,
          168,
          169,
          170,
          171,
          172,
          173,
          178,
          179,
          184,
          185,
          196,
          197,
          198,
          199,
          200,
          201,
          202,
          203,
          204,
          205,
          206,
          207,
          208,
          209,
          214,
          215,
          220,
          221
        ];
      }
    } catch (error) {
    }
    exports.inspectOpts = Object.keys(process.env).filter((key) => {
      return /^debug_/i.test(key);
    }).reduce((obj, key) => {
      const prop = key.substring(6).toLowerCase().replace(/_([a-z])/g, (_, k) => {
        return k.toUpperCase();
      });
      let val = process.env[key];
      if (/^(yes|on|true|enabled)$/i.test(val)) {
        val = true;
      } else if (/^(no|off|false|disabled)$/i.test(val)) {
        val = false;
      } else if (val === "null") {
        val = null;
      } else {
        val = Number(val);
      }
      obj[prop] = val;
      return obj;
    }, {});
    function useColors() {
      return "colors" in exports.inspectOpts ? Boolean(exports.inspectOpts.colors) : tty.isatty(process.stderr.fd);
    }
    function formatArgs(args) {
      const { namespace: name, useColors: useColors2 } = this;
      if (useColors2) {
        const c = this.color;
        const colorCode = "\x1B[3" + (c < 8 ? c : "8;5;" + c);
        const prefix = `  ${colorCode};1m${name} \x1B[0m`;
        args[0] = prefix + args[0].split("\n").join("\n" + prefix);
        args.push(colorCode + "m+" + module2.exports.humanize(this.diff) + "\x1B[0m");
      } else {
        args[0] = getDate() + name + " " + args[0];
      }
    }
    function getDate() {
      if (exports.inspectOpts.hideDate) {
        return "";
      }
      return (/* @__PURE__ */ new Date()).toISOString() + " ";
    }
    function log(...args) {
      return process.stderr.write(util.format(...args) + "\n");
    }
    function save(namespaces) {
      if (namespaces) {
        process.env.DEBUG = namespaces;
      } else {
        delete process.env.DEBUG;
      }
    }
    function load() {
      return process.env.DEBUG;
    }
    function init(debug) {
      debug.inspectOpts = {};
      const keys = Object.keys(exports.inspectOpts);
      for (let i = 0; i < keys.length; i++) {
        debug.inspectOpts[keys[i]] = exports.inspectOpts[keys[i]];
      }
    }
    module2.exports = require_common()(exports);
    var { formatters } = module2.exports;
    formatters.o = function(v) {
      this.inspectOpts.colors = this.useColors;
      return util.inspect(v, this.inspectOpts).split("\n").map((str) => str.trim()).join(" ");
    };
    formatters.O = function(v) {
      this.inspectOpts.colors = this.useColors;
      return util.inspect(v, this.inspectOpts);
    };
  }
});

// ../../node_modules/debug/src/index.js
var require_src = __commonJS({
  "../../node_modules/debug/src/index.js"(exports, module2) {
    if (typeof process === "undefined" || process.type === "renderer" || process.browser === true || process.__nwjs) {
      module2.exports = require_browser();
    } else {
      module2.exports = require_node();
    }
  }
});

// ../../node_modules/follow-redirects/debug.js
var require_debug = __commonJS({
  "../../node_modules/follow-redirects/debug.js"(exports, module2) {
    var debug;
    module2.exports = function() {
      if (!debug) {
        try {
          debug = require_src()("follow-redirects");
        } catch (error) {
        }
        if (typeof debug !== "function") {
          debug = function() {
          };
        }
      }
      debug.apply(null, arguments);
    };
  }
});

// ../../node_modules/follow-redirects/index.js
var require_follow_redirects = __commonJS({
  "../../node_modules/follow-redirects/index.js"(exports, module2) {
    var url = require("url");
    var URL = url.URL;
    var http = require("http");
    var https = require("https");
    var Writable = require("stream").Writable;
    var assert = require("assert");
    var debug = require_debug();
    var events = ["abort", "aborted", "connect", "error", "socket", "timeout"];
    var eventHandlers = /* @__PURE__ */ Object.create(null);
    events.forEach(function(event) {
      eventHandlers[event] = function(arg1, arg2, arg3) {
        this._redirectable.emit(event, arg1, arg2, arg3);
      };
    });
    var InvalidUrlError = createErrorType(
      "ERR_INVALID_URL",
      "Invalid URL",
      TypeError
    );
    var RedirectionError = createErrorType(
      "ERR_FR_REDIRECTION_FAILURE",
      "Redirected request failed"
    );
    var TooManyRedirectsError = createErrorType(
      "ERR_FR_TOO_MANY_REDIRECTS",
      "Maximum number of redirects exceeded"
    );
    var MaxBodyLengthExceededError = createErrorType(
      "ERR_FR_MAX_BODY_LENGTH_EXCEEDED",
      "Request body larger than maxBodyLength limit"
    );
    var WriteAfterEndError = createErrorType(
      "ERR_STREAM_WRITE_AFTER_END",
      "write after end"
    );
    function RedirectableRequest(options, responseCallback) {
      Writable.call(this);
      this._sanitizeOptions(options);
      this._options = options;
      this._ended = false;
      this._ending = false;
      this._redirectCount = 0;
      this._redirects = [];
      this._requestBodyLength = 0;
      this._requestBodyBuffers = [];
      if (responseCallback) {
        this.on("response", responseCallback);
      }
      var self = this;
      this._onNativeResponse = function(response) {
        self._processResponse(response);
      };
      this._performRequest();
    }
    RedirectableRequest.prototype = Object.create(Writable.prototype);
    RedirectableRequest.prototype.abort = function() {
      abortRequest(this._currentRequest);
      this.emit("abort");
    };
    RedirectableRequest.prototype.write = function(data, encoding, callback) {
      if (this._ending) {
        throw new WriteAfterEndError();
      }
      if (!isString(data) && !isBuffer(data)) {
        throw new TypeError("data should be a string, Buffer or Uint8Array");
      }
      if (isFunction(encoding)) {
        callback = encoding;
        encoding = null;
      }
      if (data.length === 0) {
        if (callback) {
          callback();
        }
        return;
      }
      if (this._requestBodyLength + data.length <= this._options.maxBodyLength) {
        this._requestBodyLength += data.length;
        this._requestBodyBuffers.push({ data, encoding });
        this._currentRequest.write(data, encoding, callback);
      } else {
        this.emit("error", new MaxBodyLengthExceededError());
        this.abort();
      }
    };
    RedirectableRequest.prototype.end = function(data, encoding, callback) {
      if (isFunction(data)) {
        callback = data;
        data = encoding = null;
      } else if (isFunction(encoding)) {
        callback = encoding;
        encoding = null;
      }
      if (!data) {
        this._ended = this._ending = true;
        this._currentRequest.end(null, null, callback);
      } else {
        var self = this;
        var currentRequest = this._currentRequest;
        this.write(data, encoding, function() {
          self._ended = true;
          currentRequest.end(null, null, callback);
        });
        this._ending = true;
      }
    };
    RedirectableRequest.prototype.setHeader = function(name, value) {
      this._options.headers[name] = value;
      this._currentRequest.setHeader(name, value);
    };
    RedirectableRequest.prototype.removeHeader = function(name) {
      delete this._options.headers[name];
      this._currentRequest.removeHeader(name);
    };
    RedirectableRequest.prototype.setTimeout = function(msecs, callback) {
      var self = this;
      function destroyOnTimeout(socket) {
        socket.setTimeout(msecs);
        socket.removeListener("timeout", socket.destroy);
        socket.addListener("timeout", socket.destroy);
      }
      function startTimer(socket) {
        if (self._timeout) {
          clearTimeout(self._timeout);
        }
        self._timeout = setTimeout(function() {
          self.emit("timeout");
          clearTimer();
        }, msecs);
        destroyOnTimeout(socket);
      }
      function clearTimer() {
        if (self._timeout) {
          clearTimeout(self._timeout);
          self._timeout = null;
        }
        self.removeListener("abort", clearTimer);
        self.removeListener("error", clearTimer);
        self.removeListener("response", clearTimer);
        if (callback) {
          self.removeListener("timeout", callback);
        }
        if (!self.socket) {
          self._currentRequest.removeListener("socket", startTimer);
        }
      }
      if (callback) {
        this.on("timeout", callback);
      }
      if (this.socket) {
        startTimer(this.socket);
      } else {
        this._currentRequest.once("socket", startTimer);
      }
      this.on("socket", destroyOnTimeout);
      this.on("abort", clearTimer);
      this.on("error", clearTimer);
      this.on("response", clearTimer);
      return this;
    };
    [
      "flushHeaders",
      "getHeader",
      "setNoDelay",
      "setSocketKeepAlive"
    ].forEach(function(method) {
      RedirectableRequest.prototype[method] = function(a, b) {
        return this._currentRequest[method](a, b);
      };
    });
    ["aborted", "connection", "socket"].forEach(function(property) {
      Object.defineProperty(RedirectableRequest.prototype, property, {
        get: function() {
          return this._currentRequest[property];
        }
      });
    });
    RedirectableRequest.prototype._sanitizeOptions = function(options) {
      if (!options.headers) {
        options.headers = {};
      }
      if (options.host) {
        if (!options.hostname) {
          options.hostname = options.host;
        }
        delete options.host;
      }
      if (!options.pathname && options.path) {
        var searchPos = options.path.indexOf("?");
        if (searchPos < 0) {
          options.pathname = options.path;
        } else {
          options.pathname = options.path.substring(0, searchPos);
          options.search = options.path.substring(searchPos);
        }
      }
    };
    RedirectableRequest.prototype._performRequest = function() {
      var protocol = this._options.protocol;
      var nativeProtocol = this._options.nativeProtocols[protocol];
      if (!nativeProtocol) {
        this.emit("error", new TypeError("Unsupported protocol " + protocol));
        return;
      }
      if (this._options.agents) {
        var scheme = protocol.slice(0, -1);
        this._options.agent = this._options.agents[scheme];
      }
      var request = this._currentRequest = nativeProtocol.request(this._options, this._onNativeResponse);
      request._redirectable = this;
      for (var event of events) {
        request.on(event, eventHandlers[event]);
      }
      this._currentUrl = /^\//.test(this._options.path) ? url.format(this._options) : (
        // When making a request to a proxy, […]
        // a client MUST send the target URI in absolute-form […].
        this._options.path
      );
      if (this._isRedirect) {
        var i = 0;
        var self = this;
        var buffers = this._requestBodyBuffers;
        (function writeNext(error) {
          if (request === self._currentRequest) {
            if (error) {
              self.emit("error", error);
            } else if (i < buffers.length) {
              var buffer = buffers[i++];
              if (!request.finished) {
                request.write(buffer.data, buffer.encoding, writeNext);
              }
            } else if (self._ended) {
              request.end();
            }
          }
        })();
      }
    };
    RedirectableRequest.prototype._processResponse = function(response) {
      var statusCode = response.statusCode;
      if (this._options.trackRedirects) {
        this._redirects.push({
          url: this._currentUrl,
          headers: response.headers,
          statusCode
        });
      }
      var location = response.headers.location;
      if (!location || this._options.followRedirects === false || statusCode < 300 || statusCode >= 400) {
        response.responseUrl = this._currentUrl;
        response.redirects = this._redirects;
        this.emit("response", response);
        this._requestBodyBuffers = [];
        return;
      }
      abortRequest(this._currentRequest);
      response.destroy();
      if (++this._redirectCount > this._options.maxRedirects) {
        this.emit("error", new TooManyRedirectsError());
        return;
      }
      var requestHeaders;
      var beforeRedirect = this._options.beforeRedirect;
      if (beforeRedirect) {
        requestHeaders = Object.assign({
          // The Host header was set by nativeProtocol.request
          Host: response.req.getHeader("host")
        }, this._options.headers);
      }
      var method = this._options.method;
      if ((statusCode === 301 || statusCode === 302) && this._options.method === "POST" || // RFC7231§6.4.4: The 303 (See Other) status code indicates that
      // the server is redirecting the user agent to a different resource […]
      // A user agent can perform a retrieval request targeting that URI
      // (a GET or HEAD request if using HTTP) […]
      statusCode === 303 && !/^(?:GET|HEAD)$/.test(this._options.method)) {
        this._options.method = "GET";
        this._requestBodyBuffers = [];
        removeMatchingHeaders(/^content-/i, this._options.headers);
      }
      var currentHostHeader = removeMatchingHeaders(/^host$/i, this._options.headers);
      var currentUrlParts = url.parse(this._currentUrl);
      var currentHost = currentHostHeader || currentUrlParts.host;
      var currentUrl = /^\w+:/.test(location) ? this._currentUrl : url.format(Object.assign(currentUrlParts, { host: currentHost }));
      var redirectUrl;
      try {
        redirectUrl = url.resolve(currentUrl, location);
      } catch (cause) {
        this.emit("error", new RedirectionError({ cause }));
        return;
      }
      debug("redirecting to", redirectUrl);
      this._isRedirect = true;
      var redirectUrlParts = url.parse(redirectUrl);
      Object.assign(this._options, redirectUrlParts);
      if (redirectUrlParts.protocol !== currentUrlParts.protocol && redirectUrlParts.protocol !== "https:" || redirectUrlParts.host !== currentHost && !isSubdomain(redirectUrlParts.host, currentHost)) {
        removeMatchingHeaders(/^(?:authorization|cookie)$/i, this._options.headers);
      }
      if (isFunction(beforeRedirect)) {
        var responseDetails = {
          headers: response.headers,
          statusCode
        };
        var requestDetails = {
          url: currentUrl,
          method,
          headers: requestHeaders
        };
        try {
          beforeRedirect(this._options, responseDetails, requestDetails);
        } catch (err) {
          this.emit("error", err);
          return;
        }
        this._sanitizeOptions(this._options);
      }
      try {
        this._performRequest();
      } catch (cause) {
        this.emit("error", new RedirectionError({ cause }));
      }
    };
    function wrap(protocols) {
      var exports2 = {
        maxRedirects: 21,
        maxBodyLength: 10 * 1024 * 1024
      };
      var nativeProtocols = {};
      Object.keys(protocols).forEach(function(scheme) {
        var protocol = scheme + ":";
        var nativeProtocol = nativeProtocols[protocol] = protocols[scheme];
        var wrappedProtocol = exports2[scheme] = Object.create(nativeProtocol);
        function request(input, options, callback) {
          if (isString(input)) {
            var parsed;
            try {
              parsed = urlToOptions(new URL(input));
            } catch (err) {
              parsed = url.parse(input);
            }
            if (!isString(parsed.protocol)) {
              throw new InvalidUrlError({ input });
            }
            input = parsed;
          } else if (URL && input instanceof URL) {
            input = urlToOptions(input);
          } else {
            callback = options;
            options = input;
            input = { protocol };
          }
          if (isFunction(options)) {
            callback = options;
            options = null;
          }
          options = Object.assign({
            maxRedirects: exports2.maxRedirects,
            maxBodyLength: exports2.maxBodyLength
          }, input, options);
          options.nativeProtocols = nativeProtocols;
          if (!isString(options.host) && !isString(options.hostname)) {
            options.hostname = "::1";
          }
          assert.equal(options.protocol, protocol, "protocol mismatch");
          debug("options", options);
          return new RedirectableRequest(options, callback);
        }
        function get(input, options, callback) {
          var wrappedRequest = wrappedProtocol.request(input, options, callback);
          wrappedRequest.end();
          return wrappedRequest;
        }
        Object.defineProperties(wrappedProtocol, {
          request: { value: request, configurable: true, enumerable: true, writable: true },
          get: { value: get, configurable: true, enumerable: true, writable: true }
        });
      });
      return exports2;
    }
    function noop() {
    }
    function urlToOptions(urlObject) {
      var options = {
        protocol: urlObject.protocol,
        hostname: urlObject.hostname.startsWith("[") ? (
          /* istanbul ignore next */
          urlObject.hostname.slice(1, -1)
        ) : urlObject.hostname,
        hash: urlObject.hash,
        search: urlObject.search,
        pathname: urlObject.pathname,
        path: urlObject.pathname + urlObject.search,
        href: urlObject.href
      };
      if (urlObject.port !== "") {
        options.port = Number(urlObject.port);
      }
      return options;
    }
    function removeMatchingHeaders(regex, headers) {
      var lastValue;
      for (var header in headers) {
        if (regex.test(header)) {
          lastValue = headers[header];
          delete headers[header];
        }
      }
      return lastValue === null || typeof lastValue === "undefined" ? void 0 : String(lastValue).trim();
    }
    function createErrorType(code, message, baseClass) {
      function CustomError(properties) {
        Error.captureStackTrace(this, this.constructor);
        Object.assign(this, properties || {});
        this.code = code;
        this.message = this.cause ? message + ": " + this.cause.message : message;
      }
      CustomError.prototype = new (baseClass || Error)();
      CustomError.prototype.constructor = CustomError;
      CustomError.prototype.name = "Error [" + code + "]";
      return CustomError;
    }
    function abortRequest(request) {
      for (var event of events) {
        request.removeListener(event, eventHandlers[event]);
      }
      request.on("error", noop);
      request.abort();
    }
    function isSubdomain(subdomain, domain) {
      assert(isString(subdomain) && isString(domain));
      var dot = subdomain.length - domain.length - 1;
      return dot > 0 && subdomain[dot] === "." && subdomain.endsWith(domain);
    }
    function isString(value) {
      return typeof value === "string" || value instanceof String;
    }
    function isFunction(value) {
      return typeof value === "function";
    }
    function isBuffer(value) {
      return typeof value === "object" && "length" in value;
    }
    module2.exports = wrap({ http, https });
    module2.exports.wrap = wrap;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/env/data.js
var require_data = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/env/data.js"(exports, module2) {
    module2.exports = {
      "version": "0.25.0"
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/adapters/http.js
var require_http = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/adapters/http.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var settle = require_settle();
    var buildFullPath = require_buildFullPath();
    var buildURL = require_buildURL();
    var http = require("http");
    var https = require("https");
    var httpFollow = require_follow_redirects().http;
    var httpsFollow = require_follow_redirects().https;
    var url = require("url");
    var zlib = require("zlib");
    var VERSION = require_data().version;
    var createError = require_createError();
    var enhanceError = require_enhanceError();
    var defaults = require_defaults();
    var Cancel = require_Cancel();
    var isHttps = /https:?/;
    function setProxy(options, proxy, location) {
      options.hostname = proxy.host;
      options.host = proxy.host;
      options.port = proxy.port;
      options.path = location;
      if (proxy.auth) {
        var base64 = Buffer.from(proxy.auth.username + ":" + proxy.auth.password, "utf8").toString("base64");
        options.headers["Proxy-Authorization"] = "Basic " + base64;
      }
      options.beforeRedirect = function beforeRedirect(redirection) {
        redirection.headers.host = redirection.host;
        setProxy(redirection, proxy, redirection.href);
      };
    }
    module2.exports = function httpAdapter(config) {
      return new Promise(function dispatchHttpRequest(resolvePromise, rejectPromise) {
        var onCanceled;
        function done() {
          if (config.cancelToken) {
            config.cancelToken.unsubscribe(onCanceled);
          }
          if (config.signal) {
            config.signal.removeEventListener("abort", onCanceled);
          }
        }
        var resolve = function resolve2(value) {
          done();
          resolvePromise(value);
        };
        var rejected = false;
        var reject = function reject2(value) {
          done();
          rejected = true;
          rejectPromise(value);
        };
        var data = config.data;
        var headers = config.headers;
        var headerNames = {};
        Object.keys(headers).forEach(function storeLowerName(name) {
          headerNames[name.toLowerCase()] = name;
        });
        if ("user-agent" in headerNames) {
          if (!headers[headerNames["user-agent"]]) {
            delete headers[headerNames["user-agent"]];
          }
        } else {
          headers["User-Agent"] = "axios/" + VERSION;
        }
        if (data && !utils.isStream(data)) {
          if (Buffer.isBuffer(data)) {
          } else if (utils.isArrayBuffer(data)) {
            data = Buffer.from(new Uint8Array(data));
          } else if (utils.isString(data)) {
            data = Buffer.from(data, "utf-8");
          } else {
            return reject(createError(
              "Data after transformation must be a string, an ArrayBuffer, a Buffer, or a Stream",
              config
            ));
          }
          if (config.maxBodyLength > -1 && data.length > config.maxBodyLength) {
            return reject(createError("Request body larger than maxBodyLength limit", config));
          }
          if (!headerNames["content-length"]) {
            headers["Content-Length"] = data.length;
          }
        }
        var auth = void 0;
        if (config.auth) {
          var username = config.auth.username || "";
          var password = config.auth.password || "";
          auth = username + ":" + password;
        }
        var fullPath = buildFullPath(config.baseURL, config.url);
        var parsed = url.parse(fullPath);
        var protocol = parsed.protocol || "http:";
        if (!auth && parsed.auth) {
          var urlAuth = parsed.auth.split(":");
          var urlUsername = urlAuth[0] || "";
          var urlPassword = urlAuth[1] || "";
          auth = urlUsername + ":" + urlPassword;
        }
        if (auth && headerNames.authorization) {
          delete headers[headerNames.authorization];
        }
        var isHttpsRequest = isHttps.test(protocol);
        var agent = isHttpsRequest ? config.httpsAgent : config.httpAgent;
        var options = {
          path: buildURL(parsed.path, config.params, config.paramsSerializer).replace(/^\?/, ""),
          method: config.method.toUpperCase(),
          headers,
          agent,
          agents: { http: config.httpAgent, https: config.httpsAgent },
          auth
        };
        if (config.socketPath) {
          options.socketPath = config.socketPath;
        } else {
          options.hostname = parsed.hostname;
          options.port = parsed.port;
        }
        var proxy = config.proxy;
        if (!proxy && proxy !== false) {
          var proxyEnv = protocol.slice(0, -1) + "_proxy";
          var proxyUrl = process.env[proxyEnv] || process.env[proxyEnv.toUpperCase()];
          if (proxyUrl) {
            var parsedProxyUrl = url.parse(proxyUrl);
            var noProxyEnv = process.env.no_proxy || process.env.NO_PROXY;
            var shouldProxy = true;
            if (noProxyEnv) {
              var noProxy = noProxyEnv.split(",").map(function trim(s) {
                return s.trim();
              });
              shouldProxy = !noProxy.some(function proxyMatch(proxyElement) {
                if (!proxyElement) {
                  return false;
                }
                if (proxyElement === "*") {
                  return true;
                }
                if (proxyElement[0] === "." && parsed.hostname.substr(parsed.hostname.length - proxyElement.length) === proxyElement) {
                  return true;
                }
                return parsed.hostname === proxyElement;
              });
            }
            if (shouldProxy) {
              proxy = {
                host: parsedProxyUrl.hostname,
                port: parsedProxyUrl.port,
                protocol: parsedProxyUrl.protocol
              };
              if (parsedProxyUrl.auth) {
                var proxyUrlAuth = parsedProxyUrl.auth.split(":");
                proxy.auth = {
                  username: proxyUrlAuth[0],
                  password: proxyUrlAuth[1]
                };
              }
            }
          }
        }
        if (proxy) {
          options.headers.host = parsed.hostname + (parsed.port ? ":" + parsed.port : "");
          setProxy(options, proxy, protocol + "//" + parsed.hostname + (parsed.port ? ":" + parsed.port : "") + options.path);
        }
        var transport;
        var isHttpsProxy = isHttpsRequest && (proxy ? isHttps.test(proxy.protocol) : true);
        if (config.transport) {
          transport = config.transport;
        } else if (config.maxRedirects === 0) {
          transport = isHttpsProxy ? https : http;
        } else {
          if (config.maxRedirects) {
            options.maxRedirects = config.maxRedirects;
          }
          transport = isHttpsProxy ? httpsFollow : httpFollow;
        }
        if (config.maxBodyLength > -1) {
          options.maxBodyLength = config.maxBodyLength;
        }
        if (config.insecureHTTPParser) {
          options.insecureHTTPParser = config.insecureHTTPParser;
        }
        var req = transport.request(options, function handleResponse(res) {
          if (req.aborted)
            return;
          var stream = res;
          var lastRequest = res.req || req;
          if (res.statusCode !== 204 && lastRequest.method !== "HEAD" && config.decompress !== false) {
            switch (res.headers["content-encoding"]) {
              case "gzip":
              case "compress":
              case "deflate":
                stream = stream.pipe(zlib.createUnzip());
                delete res.headers["content-encoding"];
                break;
            }
          }
          var response = {
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.headers,
            config,
            request: lastRequest
          };
          if (config.responseType === "stream") {
            response.data = stream;
            settle(resolve, reject, response);
          } else {
            var responseBuffer = [];
            var totalResponseBytes = 0;
            stream.on("data", function handleStreamData(chunk) {
              responseBuffer.push(chunk);
              totalResponseBytes += chunk.length;
              if (config.maxContentLength > -1 && totalResponseBytes > config.maxContentLength) {
                rejected = true;
                stream.destroy();
                reject(createError(
                  "maxContentLength size of " + config.maxContentLength + " exceeded",
                  config,
                  null,
                  lastRequest
                ));
              }
            });
            stream.on("aborted", function handlerStreamAborted() {
              if (rejected) {
                return;
              }
              stream.destroy();
              reject(createError("error request aborted", config, "ERR_REQUEST_ABORTED", lastRequest));
            });
            stream.on("error", function handleStreamError(err) {
              if (req.aborted)
                return;
              reject(enhanceError(err, config, null, lastRequest));
            });
            stream.on("end", function handleStreamEnd() {
              try {
                var responseData = responseBuffer.length === 1 ? responseBuffer[0] : Buffer.concat(responseBuffer);
                if (config.responseType !== "arraybuffer") {
                  responseData = responseData.toString(config.responseEncoding);
                  if (!config.responseEncoding || config.responseEncoding === "utf8") {
                    responseData = utils.stripBOM(responseData);
                  }
                }
                response.data = responseData;
              } catch (err) {
                reject(enhanceError(err, config, err.code, response.request, response));
              }
              settle(resolve, reject, response);
            });
          }
        });
        req.on("error", function handleRequestError(err) {
          if (req.aborted && err.code !== "ERR_FR_TOO_MANY_REDIRECTS")
            return;
          reject(enhanceError(err, config, null, req));
        });
        req.on("socket", function handleRequestSocket(socket) {
          socket.setKeepAlive(true, 1e3 * 60);
        });
        if (config.timeout) {
          var timeout = parseInt(config.timeout, 10);
          if (isNaN(timeout)) {
            reject(createError(
              "error trying to parse `config.timeout` to int",
              config,
              "ERR_PARSE_TIMEOUT",
              req
            ));
            return;
          }
          req.setTimeout(timeout, function handleRequestTimeout() {
            req.abort();
            var transitional = config.transitional || defaults.transitional;
            reject(createError(
              "timeout of " + timeout + "ms exceeded",
              config,
              transitional.clarifyTimeoutError ? "ETIMEDOUT" : "ECONNABORTED",
              req
            ));
          });
        }
        if (config.cancelToken || config.signal) {
          onCanceled = function(cancel) {
            if (req.aborted)
              return;
            req.abort();
            reject(!cancel || cancel && cancel.type ? new Cancel("canceled") : cancel);
          };
          config.cancelToken && config.cancelToken.subscribe(onCanceled);
          if (config.signal) {
            config.signal.aborted ? onCanceled() : config.signal.addEventListener("abort", onCanceled);
          }
        }
        if (utils.isStream(data)) {
          data.on("error", function handleStreamError(err) {
            reject(enhanceError(err, config, null, req));
          }).pipe(req);
        } else {
          req.end(data);
        }
      });
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/defaults.js
var require_defaults = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/defaults.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var normalizeHeaderName = require_normalizeHeaderName();
    var enhanceError = require_enhanceError();
    var DEFAULT_CONTENT_TYPE = {
      "Content-Type": "application/x-www-form-urlencoded"
    };
    function setContentTypeIfUnset(headers, value) {
      if (!utils.isUndefined(headers) && utils.isUndefined(headers["Content-Type"])) {
        headers["Content-Type"] = value;
      }
    }
    function getDefaultAdapter() {
      var adapter;
      if (typeof XMLHttpRequest !== "undefined") {
        adapter = require_xhr();
      } else if (typeof process !== "undefined" && Object.prototype.toString.call(process) === "[object process]") {
        adapter = require_http();
      }
      return adapter;
    }
    function stringifySafely(rawValue, parser, encoder) {
      if (utils.isString(rawValue)) {
        try {
          (parser || JSON.parse)(rawValue);
          return utils.trim(rawValue);
        } catch (e) {
          if (e.name !== "SyntaxError") {
            throw e;
          }
        }
      }
      return (encoder || JSON.stringify)(rawValue);
    }
    var defaults = {
      transitional: {
        silentJSONParsing: true,
        forcedJSONParsing: true,
        clarifyTimeoutError: false
      },
      adapter: getDefaultAdapter(),
      transformRequest: [function transformRequest(data, headers) {
        normalizeHeaderName(headers, "Accept");
        normalizeHeaderName(headers, "Content-Type");
        if (utils.isFormData(data) || utils.isArrayBuffer(data) || utils.isBuffer(data) || utils.isStream(data) || utils.isFile(data) || utils.isBlob(data)) {
          return data;
        }
        if (utils.isArrayBufferView(data)) {
          return data.buffer;
        }
        if (utils.isURLSearchParams(data)) {
          setContentTypeIfUnset(headers, "application/x-www-form-urlencoded;charset=utf-8");
          return data.toString();
        }
        if (utils.isObject(data) || headers && headers["Content-Type"] === "application/json") {
          setContentTypeIfUnset(headers, "application/json");
          return stringifySafely(data);
        }
        return data;
      }],
      transformResponse: [function transformResponse(data) {
        var transitional = this.transitional || defaults.transitional;
        var silentJSONParsing = transitional && transitional.silentJSONParsing;
        var forcedJSONParsing = transitional && transitional.forcedJSONParsing;
        var strictJSONParsing = !silentJSONParsing && this.responseType === "json";
        if (strictJSONParsing || forcedJSONParsing && utils.isString(data) && data.length) {
          try {
            return JSON.parse(data);
          } catch (e) {
            if (strictJSONParsing) {
              if (e.name === "SyntaxError") {
                throw enhanceError(e, this, "E_JSON_PARSE");
              }
              throw e;
            }
          }
        }
        return data;
      }],
      /**
       * A timeout in milliseconds to abort a request. If set to 0 (default) a
       * timeout is not created.
       */
      timeout: 0,
      xsrfCookieName: "XSRF-TOKEN",
      xsrfHeaderName: "X-XSRF-TOKEN",
      maxContentLength: -1,
      maxBodyLength: -1,
      validateStatus: function validateStatus(status) {
        return status >= 200 && status < 300;
      },
      headers: {
        common: {
          "Accept": "application/json, text/plain, */*"
        }
      }
    };
    utils.forEach(["delete", "get", "head"], function forEachMethodNoData(method) {
      defaults.headers[method] = {};
    });
    utils.forEach(["post", "put", "patch"], function forEachMethodWithData(method) {
      defaults.headers[method] = utils.merge(DEFAULT_CONTENT_TYPE);
    });
    module2.exports = defaults;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/transformData.js
var require_transformData = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/transformData.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var defaults = require_defaults();
    module2.exports = function transformData(data, headers, fns) {
      var context = this || defaults;
      utils.forEach(fns, function transform(fn) {
        data = fn.call(context, data, headers);
      });
      return data;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/cancel/isCancel.js
var require_isCancel = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/cancel/isCancel.js"(exports, module2) {
    "use strict";
    module2.exports = function isCancel(value) {
      return !!(value && value.__CANCEL__);
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/dispatchRequest.js
var require_dispatchRequest = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/dispatchRequest.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var transformData = require_transformData();
    var isCancel = require_isCancel();
    var defaults = require_defaults();
    var Cancel = require_Cancel();
    function throwIfCancellationRequested(config) {
      if (config.cancelToken) {
        config.cancelToken.throwIfRequested();
      }
      if (config.signal && config.signal.aborted) {
        throw new Cancel("canceled");
      }
    }
    module2.exports = function dispatchRequest(config) {
      throwIfCancellationRequested(config);
      config.headers = config.headers || {};
      config.data = transformData.call(
        config,
        config.data,
        config.headers,
        config.transformRequest
      );
      config.headers = utils.merge(
        config.headers.common || {},
        config.headers[config.method] || {},
        config.headers
      );
      utils.forEach(
        ["delete", "get", "head", "post", "put", "patch", "common"],
        function cleanHeaderConfig(method) {
          delete config.headers[method];
        }
      );
      var adapter = config.adapter || defaults.adapter;
      return adapter(config).then(function onAdapterResolution(response) {
        throwIfCancellationRequested(config);
        response.data = transformData.call(
          config,
          response.data,
          response.headers,
          config.transformResponse
        );
        return response;
      }, function onAdapterRejection(reason) {
        if (!isCancel(reason)) {
          throwIfCancellationRequested(config);
          if (reason && reason.response) {
            reason.response.data = transformData.call(
              config,
              reason.response.data,
              reason.response.headers,
              config.transformResponse
            );
          }
        }
        return Promise.reject(reason);
      });
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/mergeConfig.js
var require_mergeConfig = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/mergeConfig.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    module2.exports = function mergeConfig(config1, config2) {
      config2 = config2 || {};
      var config = {};
      function getMergedValue(target, source) {
        if (utils.isPlainObject(target) && utils.isPlainObject(source)) {
          return utils.merge(target, source);
        } else if (utils.isPlainObject(source)) {
          return utils.merge({}, source);
        } else if (utils.isArray(source)) {
          return source.slice();
        }
        return source;
      }
      function mergeDeepProperties(prop) {
        if (!utils.isUndefined(config2[prop])) {
          return getMergedValue(config1[prop], config2[prop]);
        } else if (!utils.isUndefined(config1[prop])) {
          return getMergedValue(void 0, config1[prop]);
        }
      }
      function valueFromConfig2(prop) {
        if (!utils.isUndefined(config2[prop])) {
          return getMergedValue(void 0, config2[prop]);
        }
      }
      function defaultToConfig2(prop) {
        if (!utils.isUndefined(config2[prop])) {
          return getMergedValue(void 0, config2[prop]);
        } else if (!utils.isUndefined(config1[prop])) {
          return getMergedValue(void 0, config1[prop]);
        }
      }
      function mergeDirectKeys(prop) {
        if (prop in config2) {
          return getMergedValue(config1[prop], config2[prop]);
        } else if (prop in config1) {
          return getMergedValue(void 0, config1[prop]);
        }
      }
      var mergeMap = {
        "url": valueFromConfig2,
        "method": valueFromConfig2,
        "data": valueFromConfig2,
        "baseURL": defaultToConfig2,
        "transformRequest": defaultToConfig2,
        "transformResponse": defaultToConfig2,
        "paramsSerializer": defaultToConfig2,
        "timeout": defaultToConfig2,
        "timeoutMessage": defaultToConfig2,
        "withCredentials": defaultToConfig2,
        "adapter": defaultToConfig2,
        "responseType": defaultToConfig2,
        "xsrfCookieName": defaultToConfig2,
        "xsrfHeaderName": defaultToConfig2,
        "onUploadProgress": defaultToConfig2,
        "onDownloadProgress": defaultToConfig2,
        "decompress": defaultToConfig2,
        "maxContentLength": defaultToConfig2,
        "maxBodyLength": defaultToConfig2,
        "transport": defaultToConfig2,
        "httpAgent": defaultToConfig2,
        "httpsAgent": defaultToConfig2,
        "cancelToken": defaultToConfig2,
        "socketPath": defaultToConfig2,
        "responseEncoding": defaultToConfig2,
        "validateStatus": mergeDirectKeys
      };
      utils.forEach(Object.keys(config1).concat(Object.keys(config2)), function computeConfigValue(prop) {
        var merge = mergeMap[prop] || mergeDeepProperties;
        var configValue = merge(prop);
        utils.isUndefined(configValue) && merge !== mergeDirectKeys || (config[prop] = configValue);
      });
      return config;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/validator.js
var require_validator = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/validator.js"(exports, module2) {
    "use strict";
    var VERSION = require_data().version;
    var validators = {};
    ["object", "boolean", "number", "function", "string", "symbol"].forEach(function(type, i) {
      validators[type] = function validator(thing) {
        return typeof thing === type || "a" + (i < 1 ? "n " : " ") + type;
      };
    });
    var deprecatedWarnings = {};
    validators.transitional = function transitional(validator, version, message) {
      function formatMessage(opt, desc) {
        return "[Axios v" + VERSION + "] Transitional option '" + opt + "'" + desc + (message ? ". " + message : "");
      }
      return function(value, opt, opts) {
        if (validator === false) {
          throw new Error(formatMessage(opt, " has been removed" + (version ? " in " + version : "")));
        }
        if (version && !deprecatedWarnings[opt]) {
          deprecatedWarnings[opt] = true;
          console.warn(
            formatMessage(
              opt,
              " has been deprecated since v" + version + " and will be removed in the near future"
            )
          );
        }
        return validator ? validator(value, opt, opts) : true;
      };
    };
    function assertOptions(options, schema, allowUnknown) {
      if (typeof options !== "object") {
        throw new TypeError("options must be an object");
      }
      var keys = Object.keys(options);
      var i = keys.length;
      while (i-- > 0) {
        var opt = keys[i];
        var validator = schema[opt];
        if (validator) {
          var value = options[opt];
          var result = value === void 0 || validator(value, opt, options);
          if (result !== true) {
            throw new TypeError("option " + opt + " must be " + result);
          }
          continue;
        }
        if (allowUnknown !== true) {
          throw Error("Unknown option " + opt);
        }
      }
    }
    module2.exports = {
      assertOptions,
      validators
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/core/Axios.js
var require_Axios = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/core/Axios.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var buildURL = require_buildURL();
    var InterceptorManager = require_InterceptorManager();
    var dispatchRequest = require_dispatchRequest();
    var mergeConfig = require_mergeConfig();
    var validator = require_validator();
    var validators = validator.validators;
    function Axios(instanceConfig) {
      this.defaults = instanceConfig;
      this.interceptors = {
        request: new InterceptorManager(),
        response: new InterceptorManager()
      };
    }
    Axios.prototype.request = function request(configOrUrl, config) {
      if (typeof configOrUrl === "string") {
        config = config || {};
        config.url = configOrUrl;
      } else {
        config = configOrUrl || {};
      }
      if (!config.url) {
        throw new Error("Provided config url is not valid");
      }
      config = mergeConfig(this.defaults, config);
      if (config.method) {
        config.method = config.method.toLowerCase();
      } else if (this.defaults.method) {
        config.method = this.defaults.method.toLowerCase();
      } else {
        config.method = "get";
      }
      var transitional = config.transitional;
      if (transitional !== void 0) {
        validator.assertOptions(transitional, {
          silentJSONParsing: validators.transitional(validators.boolean),
          forcedJSONParsing: validators.transitional(validators.boolean),
          clarifyTimeoutError: validators.transitional(validators.boolean)
        }, false);
      }
      var requestInterceptorChain = [];
      var synchronousRequestInterceptors = true;
      this.interceptors.request.forEach(function unshiftRequestInterceptors(interceptor) {
        if (typeof interceptor.runWhen === "function" && interceptor.runWhen(config) === false) {
          return;
        }
        synchronousRequestInterceptors = synchronousRequestInterceptors && interceptor.synchronous;
        requestInterceptorChain.unshift(interceptor.fulfilled, interceptor.rejected);
      });
      var responseInterceptorChain = [];
      this.interceptors.response.forEach(function pushResponseInterceptors(interceptor) {
        responseInterceptorChain.push(interceptor.fulfilled, interceptor.rejected);
      });
      var promise;
      if (!synchronousRequestInterceptors) {
        var chain = [dispatchRequest, void 0];
        Array.prototype.unshift.apply(chain, requestInterceptorChain);
        chain = chain.concat(responseInterceptorChain);
        promise = Promise.resolve(config);
        while (chain.length) {
          promise = promise.then(chain.shift(), chain.shift());
        }
        return promise;
      }
      var newConfig = config;
      while (requestInterceptorChain.length) {
        var onFulfilled = requestInterceptorChain.shift();
        var onRejected = requestInterceptorChain.shift();
        try {
          newConfig = onFulfilled(newConfig);
        } catch (error) {
          onRejected(error);
          break;
        }
      }
      try {
        promise = dispatchRequest(newConfig);
      } catch (error) {
        return Promise.reject(error);
      }
      while (responseInterceptorChain.length) {
        promise = promise.then(responseInterceptorChain.shift(), responseInterceptorChain.shift());
      }
      return promise;
    };
    Axios.prototype.getUri = function getUri(config) {
      if (!config.url) {
        throw new Error("Provided config url is not valid");
      }
      config = mergeConfig(this.defaults, config);
      return buildURL(config.url, config.params, config.paramsSerializer).replace(/^\?/, "");
    };
    utils.forEach(["delete", "get", "head", "options"], function forEachMethodNoData(method) {
      Axios.prototype[method] = function(url, config) {
        return this.request(mergeConfig(config || {}, {
          method,
          url,
          data: (config || {}).data
        }));
      };
    });
    utils.forEach(["post", "put", "patch"], function forEachMethodWithData(method) {
      Axios.prototype[method] = function(url, data, config) {
        return this.request(mergeConfig(config || {}, {
          method,
          url,
          data
        }));
      };
    });
    module2.exports = Axios;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/cancel/CancelToken.js
var require_CancelToken = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/cancel/CancelToken.js"(exports, module2) {
    "use strict";
    var Cancel = require_Cancel();
    function CancelToken(executor) {
      if (typeof executor !== "function") {
        throw new TypeError("executor must be a function.");
      }
      var resolvePromise;
      this.promise = new Promise(function promiseExecutor(resolve) {
        resolvePromise = resolve;
      });
      var token = this;
      this.promise.then(function(cancel) {
        if (!token._listeners)
          return;
        var i;
        var l = token._listeners.length;
        for (i = 0; i < l; i++) {
          token._listeners[i](cancel);
        }
        token._listeners = null;
      });
      this.promise.then = function(onfulfilled) {
        var _resolve;
        var promise = new Promise(function(resolve) {
          token.subscribe(resolve);
          _resolve = resolve;
        }).then(onfulfilled);
        promise.cancel = function reject() {
          token.unsubscribe(_resolve);
        };
        return promise;
      };
      executor(function cancel(message) {
        if (token.reason) {
          return;
        }
        token.reason = new Cancel(message);
        resolvePromise(token.reason);
      });
    }
    CancelToken.prototype.throwIfRequested = function throwIfRequested() {
      if (this.reason) {
        throw this.reason;
      }
    };
    CancelToken.prototype.subscribe = function subscribe(listener) {
      if (this.reason) {
        listener(this.reason);
        return;
      }
      if (this._listeners) {
        this._listeners.push(listener);
      } else {
        this._listeners = [listener];
      }
    };
    CancelToken.prototype.unsubscribe = function unsubscribe(listener) {
      if (!this._listeners) {
        return;
      }
      var index = this._listeners.indexOf(listener);
      if (index !== -1) {
        this._listeners.splice(index, 1);
      }
    };
    CancelToken.source = function source() {
      var cancel;
      var token = new CancelToken(function executor(c) {
        cancel = c;
      });
      return {
        token,
        cancel
      };
    };
    module2.exports = CancelToken;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/spread.js
var require_spread = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/spread.js"(exports, module2) {
    "use strict";
    module2.exports = function spread(callback) {
      return function wrap(arr) {
        return callback.apply(null, arr);
      };
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/isAxiosError.js
var require_isAxiosError = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/helpers/isAxiosError.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    module2.exports = function isAxiosError(payload) {
      return utils.isObject(payload) && payload.isAxiosError === true;
    };
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/lib/axios.js
var require_axios = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/lib/axios.js"(exports, module2) {
    "use strict";
    var utils = require_utils();
    var bind = require_bind();
    var Axios = require_Axios();
    var mergeConfig = require_mergeConfig();
    var defaults = require_defaults();
    function createInstance(defaultConfig) {
      var context = new Axios(defaultConfig);
      var instance = bind(Axios.prototype.request, context);
      utils.extend(instance, Axios.prototype, context);
      utils.extend(instance, context);
      instance.create = function create(instanceConfig) {
        return createInstance(mergeConfig(defaultConfig, instanceConfig));
      };
      return instance;
    }
    var axios = createInstance(defaults);
    axios.Axios = Axios;
    axios.Cancel = require_Cancel();
    axios.CancelToken = require_CancelToken();
    axios.isCancel = require_isCancel();
    axios.VERSION = require_data().version;
    axios.all = function all(promises) {
      return Promise.all(promises);
    };
    axios.spread = require_spread();
    axios.isAxiosError = require_isAxiosError();
    module2.exports = axios;
    module2.exports.default = axios;
  }
});

// ../../node_modules/cognito-at-edge/node_modules/axios/index.js
var require_axios2 = __commonJS({
  "../../node_modules/cognito-at-edge/node_modules/axios/index.js"(exports, module2) {
    module2.exports = require_axios();
  }
});

// ../../node_modules/pino-std-serializers/lib/err-helpers.js
var require_err_helpers = __commonJS({
  "../../node_modules/pino-std-serializers/lib/err-helpers.js"(exports, module2) {
    "use strict";
    var isErrorLike = (err) => {
      return err && typeof err.message === "string";
    };
    var getErrorCause = (err) => {
      if (!err)
        return;
      const cause = err.cause;
      if (typeof cause === "function") {
        const causeResult = err.cause();
        return isErrorLike(causeResult) ? causeResult : void 0;
      } else {
        return isErrorLike(cause) ? cause : void 0;
      }
    };
    var _stackWithCauses = (err, seen) => {
      if (!isErrorLike(err))
        return "";
      const stack = err.stack || "";
      if (seen.has(err)) {
        return stack + "\ncauses have become circular...";
      }
      const cause = getErrorCause(err);
      if (cause) {
        seen.add(err);
        return stack + "\ncaused by: " + _stackWithCauses(cause, seen);
      } else {
        return stack;
      }
    };
    var stackWithCauses = (err) => _stackWithCauses(err, /* @__PURE__ */ new Set());
    var _messageWithCauses = (err, seen, skip) => {
      if (!isErrorLike(err))
        return "";
      const message = skip ? "" : err.message || "";
      if (seen.has(err)) {
        return message + ": ...";
      }
      const cause = getErrorCause(err);
      if (cause) {
        seen.add(err);
        const skipIfVErrorStyleCause = typeof err.cause === "function";
        return message + (skipIfVErrorStyleCause ? "" : ": ") + _messageWithCauses(cause, seen, skipIfVErrorStyleCause);
      } else {
        return message;
      }
    };
    var messageWithCauses = (err) => _messageWithCauses(err, /* @__PURE__ */ new Set());
    module2.exports = {
      isErrorLike,
      getErrorCause,
      stackWithCauses,
      messageWithCauses
    };
  }
});

// ../../node_modules/pino-std-serializers/lib/err-proto.js
var require_err_proto = __commonJS({
  "../../node_modules/pino-std-serializers/lib/err-proto.js"(exports, module2) {
    "use strict";
    var seen = Symbol("circular-ref-tag");
    var rawSymbol = Symbol("pino-raw-err-ref");
    var pinoErrProto = Object.create({}, {
      type: {
        enumerable: true,
        writable: true,
        value: void 0
      },
      message: {
        enumerable: true,
        writable: true,
        value: void 0
      },
      stack: {
        enumerable: true,
        writable: true,
        value: void 0
      },
      aggregateErrors: {
        enumerable: true,
        writable: true,
        value: void 0
      },
      raw: {
        enumerable: false,
        get: function() {
          return this[rawSymbol];
        },
        set: function(val) {
          this[rawSymbol] = val;
        }
      }
    });
    Object.defineProperty(pinoErrProto, rawSymbol, {
      writable: true,
      value: {}
    });
    module2.exports = {
      pinoErrProto,
      pinoErrorSymbols: {
        seen,
        rawSymbol
      }
    };
  }
});

// ../../node_modules/pino-std-serializers/lib/err.js
var require_err = __commonJS({
  "../../node_modules/pino-std-serializers/lib/err.js"(exports, module2) {
    "use strict";
    module2.exports = errSerializer;
    var { messageWithCauses, stackWithCauses, isErrorLike } = require_err_helpers();
    var { pinoErrProto, pinoErrorSymbols } = require_err_proto();
    var { seen } = pinoErrorSymbols;
    var { toString } = Object.prototype;
    function errSerializer(err) {
      if (!isErrorLike(err)) {
        return err;
      }
      err[seen] = void 0;
      const _err = Object.create(pinoErrProto);
      _err.type = toString.call(err.constructor) === "[object Function]" ? err.constructor.name : err.name;
      _err.message = messageWithCauses(err);
      _err.stack = stackWithCauses(err);
      if (Array.isArray(err.errors)) {
        _err.aggregateErrors = err.errors.map((err2) => errSerializer(err2));
      }
      for (const key in err) {
        if (_err[key] === void 0) {
          const val = err[key];
          if (isErrorLike(val)) {
            if (key !== "cause" && !Object.prototype.hasOwnProperty.call(val, seen)) {
              _err[key] = errSerializer(val);
            }
          } else {
            _err[key] = val;
          }
        }
      }
      delete err[seen];
      _err.raw = err;
      return _err;
    }
  }
});

// ../../node_modules/pino-std-serializers/lib/err-with-cause.js
var require_err_with_cause = __commonJS({
  "../../node_modules/pino-std-serializers/lib/err-with-cause.js"(exports, module2) {
    "use strict";
    module2.exports = errWithCauseSerializer;
    var { isErrorLike } = require_err_helpers();
    var { pinoErrProto, pinoErrorSymbols } = require_err_proto();
    var { seen } = pinoErrorSymbols;
    var { toString } = Object.prototype;
    function errWithCauseSerializer(err) {
      if (!isErrorLike(err)) {
        return err;
      }
      err[seen] = void 0;
      const _err = Object.create(pinoErrProto);
      _err.type = toString.call(err.constructor) === "[object Function]" ? err.constructor.name : err.name;
      _err.message = err.message;
      _err.stack = err.stack;
      if (Array.isArray(err.errors)) {
        _err.aggregateErrors = err.errors.map((err2) => errWithCauseSerializer(err2));
      }
      if (isErrorLike(err.cause) && !Object.prototype.hasOwnProperty.call(err.cause, seen)) {
        _err.cause = errWithCauseSerializer(err.cause);
      }
      for (const key in err) {
        if (_err[key] === void 0) {
          const val = err[key];
          if (isErrorLike(val)) {
            if (!Object.prototype.hasOwnProperty.call(val, seen)) {
              _err[key] = errWithCauseSerializer(val);
            }
          } else {
            _err[key] = val;
          }
        }
      }
      delete err[seen];
      _err.raw = err;
      return _err;
    }
  }
});

// ../../node_modules/pino-std-serializers/lib/req.js
var require_req = __commonJS({
  "../../node_modules/pino-std-serializers/lib/req.js"(exports, module2) {
    "use strict";
    module2.exports = {
      mapHttpRequest,
      reqSerializer
    };
    var rawSymbol = Symbol("pino-raw-req-ref");
    var pinoReqProto = Object.create({}, {
      id: {
        enumerable: true,
        writable: true,
        value: ""
      },
      method: {
        enumerable: true,
        writable: true,
        value: ""
      },
      url: {
        enumerable: true,
        writable: true,
        value: ""
      },
      query: {
        enumerable: true,
        writable: true,
        value: ""
      },
      params: {
        enumerable: true,
        writable: true,
        value: ""
      },
      headers: {
        enumerable: true,
        writable: true,
        value: {}
      },
      remoteAddress: {
        enumerable: true,
        writable: true,
        value: ""
      },
      remotePort: {
        enumerable: true,
        writable: true,
        value: ""
      },
      raw: {
        enumerable: false,
        get: function() {
          return this[rawSymbol];
        },
        set: function(val) {
          this[rawSymbol] = val;
        }
      }
    });
    Object.defineProperty(pinoReqProto, rawSymbol, {
      writable: true,
      value: {}
    });
    function reqSerializer(req) {
      const connection = req.info || req.socket;
      const _req = Object.create(pinoReqProto);
      _req.id = typeof req.id === "function" ? req.id() : req.id || (req.info ? req.info.id : void 0);
      _req.method = req.method;
      if (req.originalUrl) {
        _req.url = req.originalUrl;
      } else {
        const path = req.path;
        _req.url = typeof path === "string" ? path : req.url ? req.url.path || req.url : void 0;
      }
      if (req.query) {
        _req.query = req.query;
      }
      if (req.params) {
        _req.params = req.params;
      }
      _req.headers = req.headers;
      _req.remoteAddress = connection && connection.remoteAddress;
      _req.remotePort = connection && connection.remotePort;
      _req.raw = req.raw || req;
      return _req;
    }
    function mapHttpRequest(req) {
      return {
        req: reqSerializer(req)
      };
    }
  }
});

// ../../node_modules/pino-std-serializers/lib/res.js
var require_res = __commonJS({
  "../../node_modules/pino-std-serializers/lib/res.js"(exports, module2) {
    "use strict";
    module2.exports = {
      mapHttpResponse,
      resSerializer
    };
    var rawSymbol = Symbol("pino-raw-res-ref");
    var pinoResProto = Object.create({}, {
      statusCode: {
        enumerable: true,
        writable: true,
        value: 0
      },
      headers: {
        enumerable: true,
        writable: true,
        value: ""
      },
      raw: {
        enumerable: false,
        get: function() {
          return this[rawSymbol];
        },
        set: function(val) {
          this[rawSymbol] = val;
        }
      }
    });
    Object.defineProperty(pinoResProto, rawSymbol, {
      writable: true,
      value: {}
    });
    function resSerializer(res) {
      const _res = Object.create(pinoResProto);
      _res.statusCode = res.headersSent ? res.statusCode : null;
      _res.headers = res.getHeaders ? res.getHeaders() : res._headers;
      _res.raw = res;
      return _res;
    }
    function mapHttpResponse(res) {
      return {
        res: resSerializer(res)
      };
    }
  }
});

// ../../node_modules/pino-std-serializers/index.js
var require_pino_std_serializers = __commonJS({
  "../../node_modules/pino-std-serializers/index.js"(exports, module2) {
    "use strict";
    var errSerializer = require_err();
    var errWithCauseSerializer = require_err_with_cause();
    var reqSerializers = require_req();
    var resSerializers = require_res();
    module2.exports = {
      err: errSerializer,
      errWithCause: errWithCauseSerializer,
      mapHttpRequest: reqSerializers.mapHttpRequest,
      mapHttpResponse: resSerializers.mapHttpResponse,
      req: reqSerializers.reqSerializer,
      res: resSerializers.resSerializer,
      wrapErrorSerializer: function wrapErrorSerializer(customSerializer) {
        if (customSerializer === errSerializer)
          return customSerializer;
        return function wrapErrSerializer(err) {
          return customSerializer(errSerializer(err));
        };
      },
      wrapRequestSerializer: function wrapRequestSerializer(customSerializer) {
        if (customSerializer === reqSerializers.reqSerializer)
          return customSerializer;
        return function wrappedReqSerializer(req) {
          return customSerializer(reqSerializers.reqSerializer(req));
        };
      },
      wrapResponseSerializer: function wrapResponseSerializer(customSerializer) {
        if (customSerializer === resSerializers.resSerializer)
          return customSerializer;
        return function wrappedResSerializer(res) {
          return customSerializer(resSerializers.resSerializer(res));
        };
      }
    };
  }
});

// ../../node_modules/pino/lib/caller.js
var require_caller = __commonJS({
  "../../node_modules/pino/lib/caller.js"(exports, module2) {
    "use strict";
    function noOpPrepareStackTrace(_, stack) {
      return stack;
    }
    module2.exports = function getCallers() {
      const originalPrepare = Error.prepareStackTrace;
      Error.prepareStackTrace = noOpPrepareStackTrace;
      const stack = new Error().stack;
      Error.prepareStackTrace = originalPrepare;
      if (!Array.isArray(stack)) {
        return void 0;
      }
      const entries = stack.slice(2);
      const fileNames = [];
      for (const entry of entries) {
        if (!entry) {
          continue;
        }
        fileNames.push(entry.getFileName());
      }
      return fileNames;
    };
  }
});

// ../../node_modules/fast-redact/lib/validator.js
var require_validator2 = __commonJS({
  "../../node_modules/fast-redact/lib/validator.js"(exports, module2) {
    "use strict";
    module2.exports = validator;
    function validator(opts = {}) {
      const {
        ERR_PATHS_MUST_BE_STRINGS = () => "fast-redact - Paths must be (non-empty) strings",
        ERR_INVALID_PATH = (s) => `fast-redact \u2013 Invalid path (${s})`
      } = opts;
      return function validate({ paths }) {
        paths.forEach((s) => {
          if (typeof s !== "string") {
            throw Error(ERR_PATHS_MUST_BE_STRINGS());
          }
          try {
            if (/〇/.test(s))
              throw Error();
            const expr = (s[0] === "[" ? "" : ".") + s.replace(/^\*/, "\u3007").replace(/\.\*/g, ".\u3007").replace(/\[\*\]/g, "[\u3007]");
            if (/\n|\r|;/.test(expr))
              throw Error();
            if (/\/\*/.test(expr))
              throw Error();
            Function(`
            'use strict'
            const o = new Proxy({}, { get: () => o, set: () => { throw Error() } });
            const \u3007 = null;
            o${expr}
            if ([o${expr}].length !== 1) throw Error()`)();
          } catch (e) {
            throw Error(ERR_INVALID_PATH(s));
          }
        });
      };
    }
  }
});

// ../../node_modules/fast-redact/lib/rx.js
var require_rx = __commonJS({
  "../../node_modules/fast-redact/lib/rx.js"(exports, module2) {
    "use strict";
    module2.exports = /[^.[\]]+|\[((?:.)*?)\]/g;
  }
});

// ../../node_modules/fast-redact/lib/parse.js
var require_parse = __commonJS({
  "../../node_modules/fast-redact/lib/parse.js"(exports, module2) {
    "use strict";
    var rx = require_rx();
    module2.exports = parse;
    function parse({ paths }) {
      const wildcards = [];
      var wcLen = 0;
      const secret = paths.reduce(function(o, strPath, ix) {
        var path = strPath.match(rx).map((p) => p.replace(/'|"|`/g, ""));
        const leadingBracket = strPath[0] === "[";
        path = path.map((p) => {
          if (p[0] === "[")
            return p.substr(1, p.length - 2);
          else
            return p;
        });
        const star = path.indexOf("*");
        if (star > -1) {
          const before = path.slice(0, star);
          const beforeStr = before.join(".");
          const after = path.slice(star + 1, path.length);
          const nested = after.length > 0;
          wcLen++;
          wildcards.push({
            before,
            beforeStr,
            after,
            nested
          });
        } else {
          o[strPath] = {
            path,
            val: void 0,
            precensored: false,
            circle: "",
            escPath: JSON.stringify(strPath),
            leadingBracket
          };
        }
        return o;
      }, {});
      return { wildcards, wcLen, secret };
    }
  }
});

// ../../node_modules/fast-redact/lib/redactor.js
var require_redactor = __commonJS({
  "../../node_modules/fast-redact/lib/redactor.js"(exports, module2) {
    "use strict";
    var rx = require_rx();
    module2.exports = redactor;
    function redactor({ secret, serialize, wcLen, strict, isCensorFct, censorFctTakesPath }, state) {
      const redact = Function("o", `
    if (typeof o !== 'object' || o == null) {
      ${strictImpl(strict, serialize)}
    }
    const { censor, secret } = this
    ${redactTmpl(secret, isCensorFct, censorFctTakesPath)}
    this.compileRestore()
    ${dynamicRedactTmpl(wcLen > 0, isCensorFct, censorFctTakesPath)}
    ${resultTmpl(serialize)}
  `).bind(state);
      if (serialize === false) {
        redact.restore = (o) => state.restore(o);
      }
      return redact;
    }
    function redactTmpl(secret, isCensorFct, censorFctTakesPath) {
      return Object.keys(secret).map((path) => {
        const { escPath, leadingBracket, path: arrPath } = secret[path];
        const skip = leadingBracket ? 1 : 0;
        const delim = leadingBracket ? "" : ".";
        const hops = [];
        var match;
        while ((match = rx.exec(path)) !== null) {
          const [, ix] = match;
          const { index, input } = match;
          if (index > skip)
            hops.push(input.substring(0, index - (ix ? 0 : 1)));
        }
        var existence = hops.map((p) => `o${delim}${p}`).join(" && ");
        if (existence.length === 0)
          existence += `o${delim}${path} != null`;
        else
          existence += ` && o${delim}${path} != null`;
        const circularDetection = `
      switch (true) {
        ${hops.reverse().map((p) => `
          case o${delim}${p} === censor:
            secret[${escPath}].circle = ${JSON.stringify(p)}
            break
        `).join("\n")}
      }
    `;
        const censorArgs = censorFctTakesPath ? `val, ${JSON.stringify(arrPath)}` : `val`;
        return `
      if (${existence}) {
        const val = o${delim}${path}
        if (val === censor) {
          secret[${escPath}].precensored = true
        } else {
          secret[${escPath}].val = val
          o${delim}${path} = ${isCensorFct ? `censor(${censorArgs})` : "censor"}
          ${circularDetection}
        }
      }
    `;
      }).join("\n");
    }
    function dynamicRedactTmpl(hasWildcards, isCensorFct, censorFctTakesPath) {
      return hasWildcards === true ? `
    {
      const { wildcards, wcLen, groupRedact, nestedRedact } = this
      for (var i = 0; i < wcLen; i++) {
        const { before, beforeStr, after, nested } = wildcards[i]
        if (nested === true) {
          secret[beforeStr] = secret[beforeStr] || []
          nestedRedact(secret[beforeStr], o, before, after, censor, ${isCensorFct}, ${censorFctTakesPath})
        } else secret[beforeStr] = groupRedact(o, before, censor, ${isCensorFct}, ${censorFctTakesPath})
      }
    }
  ` : "";
    }
    function resultTmpl(serialize) {
      return serialize === false ? `return o` : `
    var s = this.serialize(o)
    this.restore(o)
    return s
  `;
    }
    function strictImpl(strict, serialize) {
      return strict === true ? `throw Error('fast-redact: primitives cannot be redacted')` : serialize === false ? `return o` : `return this.serialize(o)`;
    }
  }
});

// ../../node_modules/fast-redact/lib/modifiers.js
var require_modifiers = __commonJS({
  "../../node_modules/fast-redact/lib/modifiers.js"(exports, module2) {
    "use strict";
    module2.exports = {
      groupRedact,
      groupRestore,
      nestedRedact,
      nestedRestore
    };
    function groupRestore({ keys, values, target }) {
      if (target == null)
        return;
      const length = keys.length;
      for (var i = 0; i < length; i++) {
        const k = keys[i];
        target[k] = values[i];
      }
    }
    function groupRedact(o, path, censor, isCensorFct, censorFctTakesPath) {
      const target = get(o, path);
      if (target == null)
        return { keys: null, values: null, target: null, flat: true };
      const keys = Object.keys(target);
      const keysLength = keys.length;
      const pathLength = path.length;
      const pathWithKey = censorFctTakesPath ? [...path] : void 0;
      const values = new Array(keysLength);
      for (var i = 0; i < keysLength; i++) {
        const key = keys[i];
        values[i] = target[key];
        if (censorFctTakesPath) {
          pathWithKey[pathLength] = key;
          target[key] = censor(target[key], pathWithKey);
        } else if (isCensorFct) {
          target[key] = censor(target[key]);
        } else {
          target[key] = censor;
        }
      }
      return { keys, values, target, flat: true };
    }
    function nestedRestore(instructions) {
      for (let i = 0; i < instructions.length; i++) {
        const { target, path, value } = instructions[i];
        let current = target;
        for (let i2 = path.length - 1; i2 > 0; i2--) {
          current = current[path[i2]];
        }
        current[path[0]] = value;
      }
    }
    function nestedRedact(store, o, path, ns, censor, isCensorFct, censorFctTakesPath) {
      const target = get(o, path);
      if (target == null)
        return;
      const keys = Object.keys(target);
      const keysLength = keys.length;
      for (var i = 0; i < keysLength; i++) {
        const key = keys[i];
        specialSet(store, target, key, path, ns, censor, isCensorFct, censorFctTakesPath);
      }
      return store;
    }
    function has(obj, prop) {
      return obj !== void 0 && obj !== null ? "hasOwn" in Object ? Object.hasOwn(obj, prop) : Object.prototype.hasOwnProperty.call(obj, prop) : false;
    }
    function specialSet(store, o, k, path, afterPath, censor, isCensorFct, censorFctTakesPath) {
      const afterPathLen = afterPath.length;
      const lastPathIndex = afterPathLen - 1;
      const originalKey = k;
      var i = -1;
      var n;
      var nv;
      var ov;
      var oov = null;
      var wc = null;
      var kIsWc;
      var wcov;
      var consecutive = false;
      var level = 0;
      var depth = 0;
      var redactPathCurrent = tree();
      ov = n = o[k];
      if (typeof n !== "object")
        return;
      while (n != null && ++i < afterPathLen) {
        depth += 1;
        k = afterPath[i];
        oov = ov;
        if (k !== "*" && !wc && !(typeof n === "object" && k in n)) {
          break;
        }
        if (k === "*") {
          if (wc === "*") {
            consecutive = true;
          }
          wc = k;
          if (i !== lastPathIndex) {
            continue;
          }
        }
        if (wc) {
          const wcKeys = Object.keys(n);
          for (var j = 0; j < wcKeys.length; j++) {
            const wck = wcKeys[j];
            wcov = n[wck];
            kIsWc = k === "*";
            if (consecutive) {
              redactPathCurrent = node(redactPathCurrent, wck, depth);
              level = i;
              ov = iterateNthLevel(wcov, level - 1, k, path, afterPath, censor, isCensorFct, censorFctTakesPath, originalKey, n, nv, ov, kIsWc, wck, i, lastPathIndex, redactPathCurrent, store, o[originalKey], depth + 1);
            } else {
              if (kIsWc || typeof wcov === "object" && wcov !== null && k in wcov) {
                if (kIsWc) {
                  ov = wcov;
                } else {
                  ov = wcov[k];
                }
                nv = i !== lastPathIndex ? ov : isCensorFct ? censorFctTakesPath ? censor(ov, [...path, originalKey, ...afterPath]) : censor(ov) : censor;
                if (kIsWc) {
                  const rv = restoreInstr(node(redactPathCurrent, wck, depth), ov, o[originalKey]);
                  store.push(rv);
                  n[wck] = nv;
                } else {
                  if (wcov[k] === nv) {
                  } else if (nv === void 0 && censor !== void 0 || has(wcov, k) && nv === ov) {
                    redactPathCurrent = node(redactPathCurrent, wck, depth);
                  } else {
                    redactPathCurrent = node(redactPathCurrent, wck, depth);
                    const rv = restoreInstr(node(redactPathCurrent, k, depth + 1), ov, o[originalKey]);
                    store.push(rv);
                    wcov[k] = nv;
                  }
                }
              }
            }
          }
          wc = null;
        } else {
          ov = n[k];
          redactPathCurrent = node(redactPathCurrent, k, depth);
          nv = i !== lastPathIndex ? ov : isCensorFct ? censorFctTakesPath ? censor(ov, [...path, originalKey, ...afterPath]) : censor(ov) : censor;
          if (has(n, k) && nv === ov || nv === void 0 && censor !== void 0) {
          } else {
            const rv = restoreInstr(redactPathCurrent, ov, o[originalKey]);
            store.push(rv);
            n[k] = nv;
          }
          n = n[k];
        }
        if (typeof n !== "object")
          break;
        if (ov === oov || typeof ov === "undefined") {
        }
      }
    }
    function get(o, p) {
      var i = -1;
      var l = p.length;
      var n = o;
      while (n != null && ++i < l) {
        n = n[p[i]];
      }
      return n;
    }
    function iterateNthLevel(wcov, level, k, path, afterPath, censor, isCensorFct, censorFctTakesPath, originalKey, n, nv, ov, kIsWc, wck, i, lastPathIndex, redactPathCurrent, store, parent, depth) {
      if (level === 0) {
        if (kIsWc || typeof wcov === "object" && wcov !== null && k in wcov) {
          if (kIsWc) {
            ov = wcov;
          } else {
            ov = wcov[k];
          }
          nv = i !== lastPathIndex ? ov : isCensorFct ? censorFctTakesPath ? censor(ov, [...path, originalKey, ...afterPath]) : censor(ov) : censor;
          if (kIsWc) {
            const rv = restoreInstr(redactPathCurrent, ov, parent);
            store.push(rv);
            n[wck] = nv;
          } else {
            if (wcov[k] === nv) {
            } else if (nv === void 0 && censor !== void 0 || has(wcov, k) && nv === ov) {
            } else {
              const rv = restoreInstr(node(redactPathCurrent, k, depth + 1), ov, parent);
              store.push(rv);
              wcov[k] = nv;
            }
          }
        }
      }
      for (const key in wcov) {
        if (typeof wcov[key] === "object") {
          redactPathCurrent = node(redactPathCurrent, key, depth);
          iterateNthLevel(wcov[key], level - 1, k, path, afterPath, censor, isCensorFct, censorFctTakesPath, originalKey, n, nv, ov, kIsWc, wck, i, lastPathIndex, redactPathCurrent, store, parent, depth + 1);
        }
      }
    }
    function tree() {
      return { parent: null, key: null, children: [], depth: 0 };
    }
    function node(parent, key, depth) {
      if (parent.depth === depth) {
        return node(parent.parent, key, depth);
      }
      var child = {
        parent,
        key,
        depth,
        children: []
      };
      parent.children.push(child);
      return child;
    }
    function restoreInstr(node2, value, target) {
      let current = node2;
      const path = [];
      do {
        path.push(current.key);
        current = current.parent;
      } while (current.parent != null);
      return { path, value, target };
    }
  }
});

// ../../node_modules/fast-redact/lib/restorer.js
var require_restorer = __commonJS({
  "../../node_modules/fast-redact/lib/restorer.js"(exports, module2) {
    "use strict";
    var { groupRestore, nestedRestore } = require_modifiers();
    module2.exports = restorer;
    function restorer({ secret, wcLen }) {
      return function compileRestore() {
        if (this.restore)
          return;
        const paths = Object.keys(secret);
        const resetters = resetTmpl(secret, paths);
        const hasWildcards = wcLen > 0;
        const state = hasWildcards ? { secret, groupRestore, nestedRestore } : { secret };
        this.restore = Function(
          "o",
          restoreTmpl(resetters, paths, hasWildcards)
        ).bind(state);
      };
    }
    function resetTmpl(secret, paths) {
      return paths.map((path) => {
        const { circle, escPath, leadingBracket } = secret[path];
        const delim = leadingBracket ? "" : ".";
        const reset = circle ? `o.${circle} = secret[${escPath}].val` : `o${delim}${path} = secret[${escPath}].val`;
        const clear = `secret[${escPath}].val = undefined`;
        return `
      if (secret[${escPath}].val !== undefined) {
        try { ${reset} } catch (e) {}
        ${clear}
      }
    `;
      }).join("");
    }
    function restoreTmpl(resetters, paths, hasWildcards) {
      const dynamicReset = hasWildcards === true ? `
    const keys = Object.keys(secret)
    const len = keys.length
    for (var i = len - 1; i >= ${paths.length}; i--) {
      const k = keys[i]
      const o = secret[k]
      if (o.flat === true) this.groupRestore(o)
      else this.nestedRestore(o)
      secret[k] = null
    }
  ` : "";
      return `
    const secret = this.secret
    ${dynamicReset}
    ${resetters}
    return o
  `;
    }
  }
});

// ../../node_modules/fast-redact/lib/state.js
var require_state = __commonJS({
  "../../node_modules/fast-redact/lib/state.js"(exports, module2) {
    "use strict";
    module2.exports = state;
    function state(o) {
      const {
        secret,
        censor,
        compileRestore,
        serialize,
        groupRedact,
        nestedRedact,
        wildcards,
        wcLen
      } = o;
      const builder = [{ secret, censor, compileRestore }];
      if (serialize !== false)
        builder.push({ serialize });
      if (wcLen > 0)
        builder.push({ groupRedact, nestedRedact, wildcards, wcLen });
      return Object.assign(...builder);
    }
  }
});

// ../../node_modules/fast-redact/index.js
var require_fast_redact = __commonJS({
  "../../node_modules/fast-redact/index.js"(exports, module2) {
    "use strict";
    var validator = require_validator2();
    var parse = require_parse();
    var redactor = require_redactor();
    var restorer = require_restorer();
    var { groupRedact, nestedRedact } = require_modifiers();
    var state = require_state();
    var rx = require_rx();
    var validate = validator();
    var noop = (o) => o;
    noop.restore = noop;
    var DEFAULT_CENSOR = "[REDACTED]";
    fastRedact.rx = rx;
    fastRedact.validator = validator;
    module2.exports = fastRedact;
    function fastRedact(opts = {}) {
      const paths = Array.from(new Set(opts.paths || []));
      const serialize = "serialize" in opts ? opts.serialize === false ? opts.serialize : typeof opts.serialize === "function" ? opts.serialize : JSON.stringify : JSON.stringify;
      const remove = opts.remove;
      if (remove === true && serialize !== JSON.stringify) {
        throw Error("fast-redact \u2013 remove option may only be set when serializer is JSON.stringify");
      }
      const censor = remove === true ? void 0 : "censor" in opts ? opts.censor : DEFAULT_CENSOR;
      const isCensorFct = typeof censor === "function";
      const censorFctTakesPath = isCensorFct && censor.length > 1;
      if (paths.length === 0)
        return serialize || noop;
      validate({ paths, serialize, censor });
      const { wildcards, wcLen, secret } = parse({ paths, censor });
      const compileRestore = restorer({ secret, wcLen });
      const strict = "strict" in opts ? opts.strict : true;
      return redactor({ secret, wcLen, serialize, strict, isCensorFct, censorFctTakesPath }, state({
        secret,
        censor,
        compileRestore,
        serialize,
        groupRedact,
        nestedRedact,
        wildcards,
        wcLen
      }));
    }
  }
});

// ../../node_modules/pino/lib/symbols.js
var require_symbols = __commonJS({
  "../../node_modules/pino/lib/symbols.js"(exports, module2) {
    "use strict";
    var setLevelSym = Symbol("pino.setLevel");
    var getLevelSym = Symbol("pino.getLevel");
    var levelValSym = Symbol("pino.levelVal");
    var useLevelLabelsSym = Symbol("pino.useLevelLabels");
    var useOnlyCustomLevelsSym = Symbol("pino.useOnlyCustomLevels");
    var mixinSym = Symbol("pino.mixin");
    var lsCacheSym = Symbol("pino.lsCache");
    var chindingsSym = Symbol("pino.chindings");
    var asJsonSym = Symbol("pino.asJson");
    var writeSym = Symbol("pino.write");
    var redactFmtSym = Symbol("pino.redactFmt");
    var timeSym = Symbol("pino.time");
    var timeSliceIndexSym = Symbol("pino.timeSliceIndex");
    var streamSym = Symbol("pino.stream");
    var stringifySym = Symbol("pino.stringify");
    var stringifySafeSym = Symbol("pino.stringifySafe");
    var stringifiersSym = Symbol("pino.stringifiers");
    var endSym = Symbol("pino.end");
    var formatOptsSym = Symbol("pino.formatOpts");
    var messageKeySym = Symbol("pino.messageKey");
    var errorKeySym = Symbol("pino.errorKey");
    var nestedKeySym = Symbol("pino.nestedKey");
    var nestedKeyStrSym = Symbol("pino.nestedKeyStr");
    var mixinMergeStrategySym = Symbol("pino.mixinMergeStrategy");
    var msgPrefixSym = Symbol("pino.msgPrefix");
    var wildcardFirstSym = Symbol("pino.wildcardFirst");
    var serializersSym = Symbol.for("pino.serializers");
    var formattersSym = Symbol.for("pino.formatters");
    var hooksSym = Symbol.for("pino.hooks");
    var needsMetadataGsym = Symbol.for("pino.metadata");
    module2.exports = {
      setLevelSym,
      getLevelSym,
      levelValSym,
      useLevelLabelsSym,
      mixinSym,
      lsCacheSym,
      chindingsSym,
      asJsonSym,
      writeSym,
      serializersSym,
      redactFmtSym,
      timeSym,
      timeSliceIndexSym,
      streamSym,
      stringifySym,
      stringifySafeSym,
      stringifiersSym,
      endSym,
      formatOptsSym,
      messageKeySym,
      errorKeySym,
      nestedKeySym,
      wildcardFirstSym,
      needsMetadataGsym,
      useOnlyCustomLevelsSym,
      formattersSym,
      hooksSym,
      nestedKeyStrSym,
      mixinMergeStrategySym,
      msgPrefixSym
    };
  }
});

// ../../node_modules/pino/lib/redaction.js
var require_redaction = __commonJS({
  "../../node_modules/pino/lib/redaction.js"(exports, module2) {
    "use strict";
    var fastRedact = require_fast_redact();
    var { redactFmtSym, wildcardFirstSym } = require_symbols();
    var { rx, validator } = fastRedact;
    var validate = validator({
      ERR_PATHS_MUST_BE_STRINGS: () => "pino \u2013 redacted paths must be strings",
      ERR_INVALID_PATH: (s) => `pino \u2013 redact paths array contains an invalid path (${s})`
    });
    var CENSOR = "[Redacted]";
    var strict = false;
    function redaction(opts, serialize) {
      const { paths, censor } = handle(opts);
      const shape = paths.reduce((o, str) => {
        rx.lastIndex = 0;
        const first = rx.exec(str);
        const next = rx.exec(str);
        let ns = first[1] !== void 0 ? first[1].replace(/^(?:"|'|`)(.*)(?:"|'|`)$/, "$1") : first[0];
        if (ns === "*") {
          ns = wildcardFirstSym;
        }
        if (next === null) {
          o[ns] = null;
          return o;
        }
        if (o[ns] === null) {
          return o;
        }
        const { index } = next;
        const nextPath = `${str.substr(index, str.length - 1)}`;
        o[ns] = o[ns] || [];
        if (ns !== wildcardFirstSym && o[ns].length === 0) {
          o[ns].push(...o[wildcardFirstSym] || []);
        }
        if (ns === wildcardFirstSym) {
          Object.keys(o).forEach(function(k) {
            if (o[k]) {
              o[k].push(nextPath);
            }
          });
        }
        o[ns].push(nextPath);
        return o;
      }, {});
      const result = {
        [redactFmtSym]: fastRedact({ paths, censor, serialize, strict })
      };
      const topCensor = (...args) => {
        return typeof censor === "function" ? serialize(censor(...args)) : serialize(censor);
      };
      return [...Object.keys(shape), ...Object.getOwnPropertySymbols(shape)].reduce((o, k) => {
        if (shape[k] === null) {
          o[k] = (value) => topCensor(value, [k]);
        } else {
          const wrappedCensor = typeof censor === "function" ? (value, path) => {
            return censor(value, [k, ...path]);
          } : censor;
          o[k] = fastRedact({
            paths: shape[k],
            censor: wrappedCensor,
            serialize,
            strict
          });
        }
        return o;
      }, result);
    }
    function handle(opts) {
      if (Array.isArray(opts)) {
        opts = { paths: opts, censor: CENSOR };
        validate(opts);
        return opts;
      }
      let { paths, censor = CENSOR, remove } = opts;
      if (Array.isArray(paths) === false) {
        throw Error("pino \u2013 redact must contain an array of strings");
      }
      if (remove === true)
        censor = void 0;
      validate({ paths, censor });
      return { paths, censor };
    }
    module2.exports = redaction;
  }
});

// ../../node_modules/pino/lib/time.js
var require_time = __commonJS({
  "../../node_modules/pino/lib/time.js"(exports, module2) {
    "use strict";
    var nullTime = () => "";
    var epochTime = () => `,"time":${Date.now()}`;
    var unixTime = () => `,"time":${Math.round(Date.now() / 1e3)}`;
    var isoTime = () => `,"time":"${new Date(Date.now()).toISOString()}"`;
    module2.exports = { nullTime, epochTime, unixTime, isoTime };
  }
});

// ../../node_modules/quick-format-unescaped/index.js
var require_quick_format_unescaped = __commonJS({
  "../../node_modules/quick-format-unescaped/index.js"(exports, module2) {
    "use strict";
    function tryStringify(o) {
      try {
        return JSON.stringify(o);
      } catch (e) {
        return '"[Circular]"';
      }
    }
    module2.exports = format;
    function format(f, args, opts) {
      var ss = opts && opts.stringify || tryStringify;
      var offset = 1;
      if (typeof f === "object" && f !== null) {
        var len = args.length + offset;
        if (len === 1)
          return f;
        var objects = new Array(len);
        objects[0] = ss(f);
        for (var index = 1; index < len; index++) {
          objects[index] = ss(args[index]);
        }
        return objects.join(" ");
      }
      if (typeof f !== "string") {
        return f;
      }
      var argLen = args.length;
      if (argLen === 0)
        return f;
      var str = "";
      var a = 1 - offset;
      var lastPos = -1;
      var flen = f && f.length || 0;
      for (var i = 0; i < flen; ) {
        if (f.charCodeAt(i) === 37 && i + 1 < flen) {
          lastPos = lastPos > -1 ? lastPos : 0;
          switch (f.charCodeAt(i + 1)) {
            case 100:
            case 102:
              if (a >= argLen)
                break;
              if (args[a] == null)
                break;
              if (lastPos < i)
                str += f.slice(lastPos, i);
              str += Number(args[a]);
              lastPos = i + 2;
              i++;
              break;
            case 105:
              if (a >= argLen)
                break;
              if (args[a] == null)
                break;
              if (lastPos < i)
                str += f.slice(lastPos, i);
              str += Math.floor(Number(args[a]));
              lastPos = i + 2;
              i++;
              break;
            case 79:
            case 111:
            case 106:
              if (a >= argLen)
                break;
              if (args[a] === void 0)
                break;
              if (lastPos < i)
                str += f.slice(lastPos, i);
              var type = typeof args[a];
              if (type === "string") {
                str += "'" + args[a] + "'";
                lastPos = i + 2;
                i++;
                break;
              }
              if (type === "function") {
                str += args[a].name || "<anonymous>";
                lastPos = i + 2;
                i++;
                break;
              }
              str += ss(args[a]);
              lastPos = i + 2;
              i++;
              break;
            case 115:
              if (a >= argLen)
                break;
              if (lastPos < i)
                str += f.slice(lastPos, i);
              str += String(args[a]);
              lastPos = i + 2;
              i++;
              break;
            case 37:
              if (lastPos < i)
                str += f.slice(lastPos, i);
              str += "%";
              lastPos = i + 2;
              i++;
              a--;
              break;
          }
          ++a;
        }
        ++i;
      }
      if (lastPos === -1)
        return f;
      else if (lastPos < flen) {
        str += f.slice(lastPos);
      }
      return str;
    }
  }
});

// ../../node_modules/atomic-sleep/index.js
var require_atomic_sleep = __commonJS({
  "../../node_modules/atomic-sleep/index.js"(exports, module2) {
    "use strict";
    if (typeof SharedArrayBuffer !== "undefined" && typeof Atomics !== "undefined") {
      let sleep = function(ms) {
        const valid = ms > 0 && ms < Infinity;
        if (valid === false) {
          if (typeof ms !== "number" && typeof ms !== "bigint") {
            throw TypeError("sleep: ms must be a number");
          }
          throw RangeError("sleep: ms must be a number that is greater than 0 but less than Infinity");
        }
        Atomics.wait(nil, 0, 0, Number(ms));
      };
      const nil = new Int32Array(new SharedArrayBuffer(4));
      module2.exports = sleep;
    } else {
      let sleep = function(ms) {
        const valid = ms > 0 && ms < Infinity;
        if (valid === false) {
          if (typeof ms !== "number" && typeof ms !== "bigint") {
            throw TypeError("sleep: ms must be a number");
          }
          throw RangeError("sleep: ms must be a number that is greater than 0 but less than Infinity");
        }
        const target = Date.now() + Number(ms);
        while (target > Date.now()) {
        }
      };
      module2.exports = sleep;
    }
  }
});

// ../../node_modules/sonic-boom/index.js
var require_sonic_boom = __commonJS({
  "../../node_modules/sonic-boom/index.js"(exports, module2) {
    "use strict";
    var fs = require("fs");
    var EventEmitter = require("events");
    var inherits = require("util").inherits;
    var path = require("path");
    var sleep = require_atomic_sleep();
    var BUSY_WRITE_TIMEOUT = 100;
    var MAX_WRITE = 16 * 1024;
    function openFile(file, sonic) {
      sonic._opening = true;
      sonic._writing = true;
      sonic._asyncDrainScheduled = false;
      function fileOpened(err, fd) {
        if (err) {
          sonic._reopening = false;
          sonic._writing = false;
          sonic._opening = false;
          if (sonic.sync) {
            process.nextTick(() => {
              if (sonic.listenerCount("error") > 0) {
                sonic.emit("error", err);
              }
            });
          } else {
            sonic.emit("error", err);
          }
          return;
        }
        sonic.fd = fd;
        sonic.file = file;
        sonic._reopening = false;
        sonic._opening = false;
        sonic._writing = false;
        if (sonic.sync) {
          process.nextTick(() => sonic.emit("ready"));
        } else {
          sonic.emit("ready");
        }
        if (sonic._reopening) {
          return;
        }
        if (!sonic._writing && sonic._len > sonic.minLength && !sonic.destroyed) {
          actualWrite(sonic);
        }
      }
      const flags = sonic.append ? "a" : "w";
      const mode = sonic.mode;
      if (sonic.sync) {
        try {
          if (sonic.mkdir)
            fs.mkdirSync(path.dirname(file), { recursive: true });
          const fd = fs.openSync(file, flags, mode);
          fileOpened(null, fd);
        } catch (err) {
          fileOpened(err);
          throw err;
        }
      } else if (sonic.mkdir) {
        fs.mkdir(path.dirname(file), { recursive: true }, (err) => {
          if (err)
            return fileOpened(err);
          fs.open(file, flags, mode, fileOpened);
        });
      } else {
        fs.open(file, flags, mode, fileOpened);
      }
    }
    function SonicBoom(opts) {
      if (!(this instanceof SonicBoom)) {
        return new SonicBoom(opts);
      }
      let { fd, dest, minLength, maxLength, maxWrite, sync, append = true, mode, mkdir, retryEAGAIN, fsync } = opts || {};
      fd = fd || dest;
      this._bufs = [];
      this._len = 0;
      this.fd = -1;
      this._writing = false;
      this._writingBuf = "";
      this._ending = false;
      this._reopening = false;
      this._asyncDrainScheduled = false;
      this._hwm = Math.max(minLength || 0, 16387);
      this.file = null;
      this.destroyed = false;
      this.minLength = minLength || 0;
      this.maxLength = maxLength || 0;
      this.maxWrite = maxWrite || MAX_WRITE;
      this.sync = sync || false;
      this._fsync = fsync || false;
      this.append = append || false;
      this.mode = mode;
      this.retryEAGAIN = retryEAGAIN || (() => true);
      this.mkdir = mkdir || false;
      if (typeof fd === "number") {
        this.fd = fd;
        process.nextTick(() => this.emit("ready"));
      } else if (typeof fd === "string") {
        openFile(fd, this);
      } else {
        throw new Error("SonicBoom supports only file descriptors and files");
      }
      if (this.minLength >= this.maxWrite) {
        throw new Error(`minLength should be smaller than maxWrite (${this.maxWrite})`);
      }
      this.release = (err, n) => {
        if (err) {
          if ((err.code === "EAGAIN" || err.code === "EBUSY") && this.retryEAGAIN(err, this._writingBuf.length, this._len - this._writingBuf.length)) {
            if (this.sync) {
              try {
                sleep(BUSY_WRITE_TIMEOUT);
                this.release(void 0, 0);
              } catch (err2) {
                this.release(err2);
              }
            } else {
              setTimeout(() => {
                fs.write(this.fd, this._writingBuf, "utf8", this.release);
              }, BUSY_WRITE_TIMEOUT);
            }
          } else {
            this._writing = false;
            this.emit("error", err);
          }
          return;
        }
        this.emit("write", n);
        this._len -= n;
        if (this._len < 0) {
          this._len = 0;
        }
        this._writingBuf = this._writingBuf.slice(n);
        if (this._writingBuf.length) {
          if (!this.sync) {
            fs.write(this.fd, this._writingBuf, "utf8", this.release);
            return;
          }
          try {
            do {
              const n2 = fs.writeSync(this.fd, this._writingBuf, "utf8");
              this._len -= n2;
              this._writingBuf = this._writingBuf.slice(n2);
            } while (this._writingBuf);
          } catch (err2) {
            this.release(err2);
            return;
          }
        }
        if (this._fsync) {
          fs.fsyncSync(this.fd);
        }
        const len = this._len;
        if (this._reopening) {
          this._writing = false;
          this._reopening = false;
          this.reopen();
        } else if (len > this.minLength) {
          actualWrite(this);
        } else if (this._ending) {
          if (len > 0) {
            actualWrite(this);
          } else {
            this._writing = false;
            actualClose(this);
          }
        } else {
          this._writing = false;
          if (this.sync) {
            if (!this._asyncDrainScheduled) {
              this._asyncDrainScheduled = true;
              process.nextTick(emitDrain, this);
            }
          } else {
            this.emit("drain");
          }
        }
      };
      this.on("newListener", function(name) {
        if (name === "drain") {
          this._asyncDrainScheduled = false;
        }
      });
    }
    function emitDrain(sonic) {
      const hasListeners = sonic.listenerCount("drain") > 0;
      if (!hasListeners)
        return;
      sonic._asyncDrainScheduled = false;
      sonic.emit("drain");
    }
    inherits(SonicBoom, EventEmitter);
    SonicBoom.prototype.write = function(data) {
      if (this.destroyed) {
        throw new Error("SonicBoom destroyed");
      }
      const len = this._len + data.length;
      const bufs = this._bufs;
      if (this.maxLength && len > this.maxLength) {
        this.emit("drop", data);
        return this._len < this._hwm;
      }
      if (bufs.length === 0 || bufs[bufs.length - 1].length + data.length > this.maxWrite) {
        bufs.push("" + data);
      } else {
        bufs[bufs.length - 1] += data;
      }
      this._len = len;
      if (!this._writing && this._len >= this.minLength) {
        actualWrite(this);
      }
      return this._len < this._hwm;
    };
    SonicBoom.prototype.flush = function() {
      if (this.destroyed) {
        throw new Error("SonicBoom destroyed");
      }
      if (this._writing || this.minLength <= 0) {
        return;
      }
      if (this._bufs.length === 0) {
        this._bufs.push("");
      }
      actualWrite(this);
    };
    SonicBoom.prototype.reopen = function(file) {
      if (this.destroyed) {
        throw new Error("SonicBoom destroyed");
      }
      if (this._opening) {
        this.once("ready", () => {
          this.reopen(file);
        });
        return;
      }
      if (this._ending) {
        return;
      }
      if (!this.file) {
        throw new Error("Unable to reopen a file descriptor, you must pass a file to SonicBoom");
      }
      this._reopening = true;
      if (this._writing) {
        return;
      }
      const fd = this.fd;
      this.once("ready", () => {
        if (fd !== this.fd) {
          fs.close(fd, (err) => {
            if (err) {
              return this.emit("error", err);
            }
          });
        }
      });
      openFile(file || this.file, this);
    };
    SonicBoom.prototype.end = function() {
      if (this.destroyed) {
        throw new Error("SonicBoom destroyed");
      }
      if (this._opening) {
        this.once("ready", () => {
          this.end();
        });
        return;
      }
      if (this._ending) {
        return;
      }
      this._ending = true;
      if (this._writing) {
        return;
      }
      if (this._len > 0 && this.fd >= 0) {
        actualWrite(this);
      } else {
        actualClose(this);
      }
    };
    SonicBoom.prototype.flushSync = function() {
      if (this.destroyed) {
        throw new Error("SonicBoom destroyed");
      }
      if (this.fd < 0) {
        throw new Error("sonic boom is not ready yet");
      }
      if (!this._writing && this._writingBuf.length > 0) {
        this._bufs.unshift(this._writingBuf);
        this._writingBuf = "";
      }
      let buf = "";
      while (this._bufs.length || buf.length) {
        if (buf.length <= 0) {
          buf = this._bufs[0];
        }
        try {
          const n = fs.writeSync(this.fd, buf, "utf8");
          buf = buf.slice(n);
          this._len = Math.max(this._len - n, 0);
          if (buf.length <= 0) {
            this._bufs.shift();
          }
        } catch (err) {
          const shouldRetry = err.code === "EAGAIN" || err.code === "EBUSY";
          if (shouldRetry && !this.retryEAGAIN(err, buf.length, this._len - buf.length)) {
            throw err;
          }
          sleep(BUSY_WRITE_TIMEOUT);
        }
      }
    };
    SonicBoom.prototype.destroy = function() {
      if (this.destroyed) {
        return;
      }
      actualClose(this);
    };
    function actualWrite(sonic) {
      const release = sonic.release;
      sonic._writing = true;
      sonic._writingBuf = sonic._writingBuf || sonic._bufs.shift() || "";
      if (sonic.sync) {
        try {
          const written = fs.writeSync(sonic.fd, sonic._writingBuf, "utf8");
          release(null, written);
        } catch (err) {
          release(err);
        }
      } else {
        fs.write(sonic.fd, sonic._writingBuf, "utf8", release);
      }
    }
    function actualClose(sonic) {
      if (sonic.fd === -1) {
        sonic.once("ready", actualClose.bind(null, sonic));
        return;
      }
      sonic.destroyed = true;
      sonic._bufs = [];
      if (sonic.fd !== 1 && sonic.fd !== 2) {
        fs.close(sonic.fd, done);
      } else {
        setImmediate(done);
      }
      function done(err) {
        if (err) {
          sonic.emit("error", err);
          return;
        }
        if (sonic._ending && !sonic._writing) {
          sonic.emit("finish");
        }
        sonic.emit("close");
      }
    }
    SonicBoom.SonicBoom = SonicBoom;
    SonicBoom.default = SonicBoom;
    module2.exports = SonicBoom;
  }
});

// ../../node_modules/on-exit-leak-free/index.js
var require_on_exit_leak_free = __commonJS({
  "../../node_modules/on-exit-leak-free/index.js"(exports, module2) {
    "use strict";
    var refs = {
      exit: [],
      beforeExit: []
    };
    var functions = {
      exit: onExit,
      beforeExit: onBeforeExit
    };
    var registry = new FinalizationRegistry(clear);
    function install(event) {
      if (refs[event].length > 0) {
        return;
      }
      process.on(event, functions[event]);
    }
    function uninstall(event) {
      if (refs[event].length > 0) {
        return;
      }
      process.removeListener(event, functions[event]);
    }
    function onExit() {
      callRefs("exit");
    }
    function onBeforeExit() {
      callRefs("beforeExit");
    }
    function callRefs(event) {
      for (const ref of refs[event]) {
        const obj = ref.deref();
        const fn = ref.fn;
        if (obj !== void 0) {
          fn(obj, event);
        }
      }
    }
    function clear(ref) {
      for (const event of ["exit", "beforeExit"]) {
        const index = refs[event].indexOf(ref);
        refs[event].splice(index, index + 1);
        uninstall(event);
      }
    }
    function _register(event, obj, fn) {
      if (obj === void 0) {
        throw new Error("the object can't be undefined");
      }
      install(event);
      const ref = new WeakRef(obj);
      ref.fn = fn;
      registry.register(obj, ref);
      refs[event].push(ref);
    }
    function register(obj, fn) {
      _register("exit", obj, fn);
    }
    function registerBeforeExit(obj, fn) {
      _register("beforeExit", obj, fn);
    }
    function unregister(obj) {
      registry.unregister(obj);
      for (const event of ["exit", "beforeExit"]) {
        refs[event] = refs[event].filter((ref) => {
          const _obj = ref.deref();
          return _obj && _obj !== obj;
        });
        uninstall(event);
      }
    }
    module2.exports = {
      register,
      registerBeforeExit,
      unregister
    };
  }
});

// ../../node_modules/thread-stream/package.json
var require_package = __commonJS({
  "../../node_modules/thread-stream/package.json"(exports, module2) {
    module2.exports = {
      name: "thread-stream",
      version: "2.3.0",
      description: "A streaming way to send data to a Node.js Worker Thread",
      main: "index.js",
      types: "index.d.ts",
      dependencies: {
        "real-require": "^0.2.0"
      },
      devDependencies: {
        "@types/node": "^18.0.0",
        "@types/tap": "^15.0.0",
        desm: "^1.3.0",
        fastbench: "^1.0.1",
        husky: "^8.0.1",
        "sonic-boom": "^3.0.0",
        standard: "^17.0.0",
        tap: "^16.2.0",
        "ts-node": "^10.8.0",
        typescript: "^4.7.2",
        "why-is-node-running": "^2.2.2"
      },
      scripts: {
        test: "standard && npm run transpile && tap test/*.test.*js && tap --ts test/*.test.*ts",
        "test:ci": "standard && npm run transpile && npm run test:ci:js && npm run test:ci:ts",
        "test:ci:js": 'tap --no-check-coverage --coverage-report=lcovonly "test/**/*.test.*js"',
        "test:ci:ts": 'tap --ts --no-check-coverage --coverage-report=lcovonly "test/**/*.test.*ts"',
        "test:yarn": 'npm run transpile && tap "test/**/*.test.js" --no-check-coverage',
        transpile: "sh ./test/ts/transpile.sh",
        prepare: "husky install"
      },
      standard: { ignore: ["test/ts/**/*"] },
      repository: {
        type: "git",
        url: "git+https://github.com/mcollina/thread-stream.git"
      },
      keywords: [
        "worker",
        "thread",
        "threads",
        "stream"
      ],
      author: "Matteo Collina <hello@matteocollina.com>",
      license: "MIT",
      bugs: {
        url: "https://github.com/mcollina/thread-stream/issues"
      },
      homepage: "https://github.com/mcollina/thread-stream#readme"
    };
  }
});

// ../../node_modules/thread-stream/lib/wait.js
var require_wait = __commonJS({
  "../../node_modules/thread-stream/lib/wait.js"(exports, module2) {
    "use strict";
    var MAX_TIMEOUT = 1e3;
    function wait(state, index, expected, timeout, done) {
      const max = Date.now() + timeout;
      let current = Atomics.load(state, index);
      if (current === expected) {
        done(null, "ok");
        return;
      }
      let prior = current;
      const check = (backoff) => {
        if (Date.now() > max) {
          done(null, "timed-out");
        } else {
          setTimeout(() => {
            prior = current;
            current = Atomics.load(state, index);
            if (current === prior) {
              check(backoff >= MAX_TIMEOUT ? MAX_TIMEOUT : backoff * 2);
            } else {
              if (current === expected)
                done(null, "ok");
              else
                done(null, "not-equal");
            }
          }, backoff);
        }
      };
      check(1);
    }
    function waitDiff(state, index, expected, timeout, done) {
      const max = Date.now() + timeout;
      let current = Atomics.load(state, index);
      if (current !== expected) {
        done(null, "ok");
        return;
      }
      const check = (backoff) => {
        if (Date.now() > max) {
          done(null, "timed-out");
        } else {
          setTimeout(() => {
            current = Atomics.load(state, index);
            if (current !== expected) {
              done(null, "ok");
            } else {
              check(backoff >= MAX_TIMEOUT ? MAX_TIMEOUT : backoff * 2);
            }
          }, backoff);
        }
      };
      check(1);
    }
    module2.exports = { wait, waitDiff };
  }
});

// ../../node_modules/thread-stream/lib/indexes.js
var require_indexes = __commonJS({
  "../../node_modules/thread-stream/lib/indexes.js"(exports, module2) {
    "use strict";
    var WRITE_INDEX = 4;
    var READ_INDEX = 8;
    module2.exports = {
      WRITE_INDEX,
      READ_INDEX
    };
  }
});

// ../../node_modules/thread-stream/index.js
var require_thread_stream = __commonJS({
  "../../node_modules/thread-stream/index.js"(exports, module2) {
    "use strict";
    var { version } = require_package();
    var { EventEmitter } = require("events");
    var { Worker } = require("worker_threads");
    var { join } = require("path");
    var { pathToFileURL } = require("url");
    var { wait } = require_wait();
    var {
      WRITE_INDEX,
      READ_INDEX
    } = require_indexes();
    var buffer = require("buffer");
    var assert = require("assert");
    var kImpl = Symbol("kImpl");
    var MAX_STRING = buffer.constants.MAX_STRING_LENGTH;
    var FakeWeakRef = class {
      constructor(value) {
        this._value = value;
      }
      deref() {
        return this._value;
      }
    };
    var FinalizationRegistry2 = global.FinalizationRegistry || class FakeFinalizationRegistry {
      register() {
      }
      unregister() {
      }
    };
    var WeakRef2 = global.WeakRef || FakeWeakRef;
    var registry = new FinalizationRegistry2((worker) => {
      if (worker.exited) {
        return;
      }
      worker.terminate();
    });
    function createWorker(stream, opts) {
      const { filename, workerData } = opts;
      const bundlerOverrides = "__bundlerPathsOverrides" in globalThis ? globalThis.__bundlerPathsOverrides : {};
      const toExecute = bundlerOverrides["thread-stream-worker"] || join(__dirname, "lib", "worker.js");
      const worker = new Worker(toExecute, {
        ...opts.workerOpts,
        trackUnmanagedFds: false,
        workerData: {
          filename: filename.indexOf("file://") === 0 ? filename : pathToFileURL(filename).href,
          dataBuf: stream[kImpl].dataBuf,
          stateBuf: stream[kImpl].stateBuf,
          workerData: {
            $context: {
              threadStreamVersion: version
            },
            ...workerData
          }
        }
      });
      worker.stream = new FakeWeakRef(stream);
      worker.on("message", onWorkerMessage);
      worker.on("exit", onWorkerExit);
      registry.register(stream, worker);
      return worker;
    }
    function drain(stream) {
      assert(!stream[kImpl].sync);
      if (stream[kImpl].needDrain) {
        stream[kImpl].needDrain = false;
        stream.emit("drain");
      }
    }
    function nextFlush(stream) {
      const writeIndex = Atomics.load(stream[kImpl].state, WRITE_INDEX);
      let leftover = stream[kImpl].data.length - writeIndex;
      if (leftover > 0) {
        if (stream[kImpl].buf.length === 0) {
          stream[kImpl].flushing = false;
          if (stream[kImpl].ending) {
            end(stream);
          } else if (stream[kImpl].needDrain) {
            process.nextTick(drain, stream);
          }
          return;
        }
        let toWrite = stream[kImpl].buf.slice(0, leftover);
        let toWriteBytes = Buffer.byteLength(toWrite);
        if (toWriteBytes <= leftover) {
          stream[kImpl].buf = stream[kImpl].buf.slice(leftover);
          write(stream, toWrite, nextFlush.bind(null, stream));
        } else {
          stream.flush(() => {
            if (stream.destroyed) {
              return;
            }
            Atomics.store(stream[kImpl].state, READ_INDEX, 0);
            Atomics.store(stream[kImpl].state, WRITE_INDEX, 0);
            while (toWriteBytes > stream[kImpl].data.length) {
              leftover = leftover / 2;
              toWrite = stream[kImpl].buf.slice(0, leftover);
              toWriteBytes = Buffer.byteLength(toWrite);
            }
            stream[kImpl].buf = stream[kImpl].buf.slice(leftover);
            write(stream, toWrite, nextFlush.bind(null, stream));
          });
        }
      } else if (leftover === 0) {
        if (writeIndex === 0 && stream[kImpl].buf.length === 0) {
          return;
        }
        stream.flush(() => {
          Atomics.store(stream[kImpl].state, READ_INDEX, 0);
          Atomics.store(stream[kImpl].state, WRITE_INDEX, 0);
          nextFlush(stream);
        });
      } else {
        destroy(stream, new Error("overwritten"));
      }
    }
    function onWorkerMessage(msg) {
      const stream = this.stream.deref();
      if (stream === void 0) {
        this.exited = true;
        this.terminate();
        return;
      }
      switch (msg.code) {
        case "READY":
          this.stream = new WeakRef2(stream);
          stream.flush(() => {
            stream[kImpl].ready = true;
            stream.emit("ready");
          });
          break;
        case "ERROR":
          destroy(stream, msg.err);
          break;
        case "EVENT":
          if (Array.isArray(msg.args)) {
            stream.emit(msg.name, ...msg.args);
          } else {
            stream.emit(msg.name, msg.args);
          }
          break;
        default:
          destroy(stream, new Error("this should not happen: " + msg.code));
      }
    }
    function onWorkerExit(code) {
      const stream = this.stream.deref();
      if (stream === void 0) {
        return;
      }
      registry.unregister(stream);
      stream.worker.exited = true;
      stream.worker.off("exit", onWorkerExit);
      destroy(stream, code !== 0 ? new Error("the worker thread exited") : null);
    }
    var ThreadStream = class extends EventEmitter {
      constructor(opts = {}) {
        super();
        if (opts.bufferSize < 4) {
          throw new Error("bufferSize must at least fit a 4-byte utf-8 char");
        }
        this[kImpl] = {};
        this[kImpl].stateBuf = new SharedArrayBuffer(128);
        this[kImpl].state = new Int32Array(this[kImpl].stateBuf);
        this[kImpl].dataBuf = new SharedArrayBuffer(opts.bufferSize || 4 * 1024 * 1024);
        this[kImpl].data = Buffer.from(this[kImpl].dataBuf);
        this[kImpl].sync = opts.sync || false;
        this[kImpl].ending = false;
        this[kImpl].ended = false;
        this[kImpl].needDrain = false;
        this[kImpl].destroyed = false;
        this[kImpl].flushing = false;
        this[kImpl].ready = false;
        this[kImpl].finished = false;
        this[kImpl].errored = null;
        this[kImpl].closed = false;
        this[kImpl].buf = "";
        this.worker = createWorker(this, opts);
      }
      write(data) {
        if (this[kImpl].destroyed) {
          error(this, new Error("the worker has exited"));
          return false;
        }
        if (this[kImpl].ending) {
          error(this, new Error("the worker is ending"));
          return false;
        }
        if (this[kImpl].flushing && this[kImpl].buf.length + data.length >= MAX_STRING) {
          try {
            writeSync(this);
            this[kImpl].flushing = true;
          } catch (err) {
            destroy(this, err);
            return false;
          }
        }
        this[kImpl].buf += data;
        if (this[kImpl].sync) {
          try {
            writeSync(this);
            return true;
          } catch (err) {
            destroy(this, err);
            return false;
          }
        }
        if (!this[kImpl].flushing) {
          this[kImpl].flushing = true;
          setImmediate(nextFlush, this);
        }
        this[kImpl].needDrain = this[kImpl].data.length - this[kImpl].buf.length - Atomics.load(this[kImpl].state, WRITE_INDEX) <= 0;
        return !this[kImpl].needDrain;
      }
      end() {
        if (this[kImpl].destroyed) {
          return;
        }
        this[kImpl].ending = true;
        end(this);
      }
      flush(cb) {
        if (this[kImpl].destroyed) {
          if (typeof cb === "function") {
            process.nextTick(cb, new Error("the worker has exited"));
          }
          return;
        }
        const writeIndex = Atomics.load(this[kImpl].state, WRITE_INDEX);
        wait(this[kImpl].state, READ_INDEX, writeIndex, Infinity, (err, res) => {
          if (err) {
            destroy(this, err);
            process.nextTick(cb, err);
            return;
          }
          if (res === "not-equal") {
            this.flush(cb);
            return;
          }
          process.nextTick(cb);
        });
      }
      flushSync() {
        if (this[kImpl].destroyed) {
          return;
        }
        writeSync(this);
        flushSync(this);
      }
      unref() {
        this.worker.unref();
      }
      ref() {
        this.worker.ref();
      }
      get ready() {
        return this[kImpl].ready;
      }
      get destroyed() {
        return this[kImpl].destroyed;
      }
      get closed() {
        return this[kImpl].closed;
      }
      get writable() {
        return !this[kImpl].destroyed && !this[kImpl].ending;
      }
      get writableEnded() {
        return this[kImpl].ending;
      }
      get writableFinished() {
        return this[kImpl].finished;
      }
      get writableNeedDrain() {
        return this[kImpl].needDrain;
      }
      get writableObjectMode() {
        return false;
      }
      get writableErrored() {
        return this[kImpl].errored;
      }
    };
    function error(stream, err) {
      setImmediate(() => {
        stream.emit("error", err);
      });
    }
    function destroy(stream, err) {
      if (stream[kImpl].destroyed) {
        return;
      }
      stream[kImpl].destroyed = true;
      if (err) {
        stream[kImpl].errored = err;
        error(stream, err);
      }
      if (!stream.worker.exited) {
        stream.worker.terminate().catch(() => {
        }).then(() => {
          stream[kImpl].closed = true;
          stream.emit("close");
        });
      } else {
        setImmediate(() => {
          stream[kImpl].closed = true;
          stream.emit("close");
        });
      }
    }
    function write(stream, data, cb) {
      const current = Atomics.load(stream[kImpl].state, WRITE_INDEX);
      const length = Buffer.byteLength(data);
      stream[kImpl].data.write(data, current);
      Atomics.store(stream[kImpl].state, WRITE_INDEX, current + length);
      Atomics.notify(stream[kImpl].state, WRITE_INDEX);
      cb();
      return true;
    }
    function end(stream) {
      if (stream[kImpl].ended || !stream[kImpl].ending || stream[kImpl].flushing) {
        return;
      }
      stream[kImpl].ended = true;
      try {
        stream.flushSync();
        let readIndex = Atomics.load(stream[kImpl].state, READ_INDEX);
        Atomics.store(stream[kImpl].state, WRITE_INDEX, -1);
        Atomics.notify(stream[kImpl].state, WRITE_INDEX);
        let spins = 0;
        while (readIndex !== -1) {
          Atomics.wait(stream[kImpl].state, READ_INDEX, readIndex, 1e3);
          readIndex = Atomics.load(stream[kImpl].state, READ_INDEX);
          if (readIndex === -2) {
            destroy(stream, new Error("end() failed"));
            return;
          }
          if (++spins === 10) {
            destroy(stream, new Error("end() took too long (10s)"));
            return;
          }
        }
        process.nextTick(() => {
          stream[kImpl].finished = true;
          stream.emit("finish");
        });
      } catch (err) {
        destroy(stream, err);
      }
    }
    function writeSync(stream) {
      const cb = () => {
        if (stream[kImpl].ending) {
          end(stream);
        } else if (stream[kImpl].needDrain) {
          process.nextTick(drain, stream);
        }
      };
      stream[kImpl].flushing = false;
      while (stream[kImpl].buf.length !== 0) {
        const writeIndex = Atomics.load(stream[kImpl].state, WRITE_INDEX);
        let leftover = stream[kImpl].data.length - writeIndex;
        if (leftover === 0) {
          flushSync(stream);
          Atomics.store(stream[kImpl].state, READ_INDEX, 0);
          Atomics.store(stream[kImpl].state, WRITE_INDEX, 0);
          continue;
        } else if (leftover < 0) {
          throw new Error("overwritten");
        }
        let toWrite = stream[kImpl].buf.slice(0, leftover);
        let toWriteBytes = Buffer.byteLength(toWrite);
        if (toWriteBytes <= leftover) {
          stream[kImpl].buf = stream[kImpl].buf.slice(leftover);
          write(stream, toWrite, cb);
        } else {
          flushSync(stream);
          Atomics.store(stream[kImpl].state, READ_INDEX, 0);
          Atomics.store(stream[kImpl].state, WRITE_INDEX, 0);
          while (toWriteBytes > stream[kImpl].buf.length) {
            leftover = leftover / 2;
            toWrite = stream[kImpl].buf.slice(0, leftover);
            toWriteBytes = Buffer.byteLength(toWrite);
          }
          stream[kImpl].buf = stream[kImpl].buf.slice(leftover);
          write(stream, toWrite, cb);
        }
      }
    }
    function flushSync(stream) {
      if (stream[kImpl].flushing) {
        throw new Error("unable to flush while flushing");
      }
      const writeIndex = Atomics.load(stream[kImpl].state, WRITE_INDEX);
      let spins = 0;
      while (true) {
        const readIndex = Atomics.load(stream[kImpl].state, READ_INDEX);
        if (readIndex === -2) {
          throw Error("_flushSync failed");
        }
        if (readIndex !== writeIndex) {
          Atomics.wait(stream[kImpl].state, READ_INDEX, readIndex, 1e3);
        } else {
          break;
        }
        if (++spins === 10) {
          throw new Error("_flushSync took too long (10s)");
        }
      }
    }
    module2.exports = ThreadStream;
  }
});

// ../../node_modules/pino/lib/transport.js
var require_transport = __commonJS({
  "../../node_modules/pino/lib/transport.js"(exports, module2) {
    "use strict";
    var { createRequire } = require("module");
    var getCallers = require_caller();
    var { join, isAbsolute, sep } = require("path");
    var sleep = require_atomic_sleep();
    var onExit = require_on_exit_leak_free();
    var ThreadStream = require_thread_stream();
    function setupOnExit(stream) {
      onExit.register(stream, autoEnd);
      onExit.registerBeforeExit(stream, flush);
      stream.on("close", function() {
        onExit.unregister(stream);
      });
    }
    function buildStream(filename, workerData, workerOpts) {
      const stream = new ThreadStream({
        filename,
        workerData,
        workerOpts
      });
      stream.on("ready", onReady);
      stream.on("close", function() {
        process.removeListener("exit", onExit2);
      });
      process.on("exit", onExit2);
      function onReady() {
        process.removeListener("exit", onExit2);
        stream.unref();
        if (workerOpts.autoEnd !== false) {
          setupOnExit(stream);
        }
      }
      function onExit2() {
        if (stream.closed) {
          return;
        }
        stream.flushSync();
        sleep(100);
        stream.end();
      }
      return stream;
    }
    function autoEnd(stream) {
      stream.ref();
      stream.flushSync();
      stream.end();
      stream.once("close", function() {
        stream.unref();
      });
    }
    function flush(stream) {
      stream.flushSync();
    }
    function transport(fullOptions) {
      const { pipeline, targets, levels, dedupe, options = {}, worker = {}, caller = getCallers() } = fullOptions;
      const callers = typeof caller === "string" ? [caller] : caller;
      const bundlerOverrides = "__bundlerPathsOverrides" in globalThis ? globalThis.__bundlerPathsOverrides : {};
      let target = fullOptions.target;
      if (target && targets) {
        throw new Error("only one of target or targets can be specified");
      }
      if (targets) {
        target = bundlerOverrides["pino-worker"] || join(__dirname, "worker.js");
        options.targets = targets.map((dest) => {
          return {
            ...dest,
            target: fixTarget(dest.target)
          };
        });
      } else if (pipeline) {
        target = bundlerOverrides["pino-pipeline-worker"] || join(__dirname, "worker-pipeline.js");
        options.targets = pipeline.map((dest) => {
          return {
            ...dest,
            target: fixTarget(dest.target)
          };
        });
      }
      if (levels) {
        options.levels = levels;
      }
      if (dedupe) {
        options.dedupe = dedupe;
      }
      return buildStream(fixTarget(target), options, worker);
      function fixTarget(origin) {
        origin = bundlerOverrides[origin] || origin;
        if (isAbsolute(origin) || origin.indexOf("file://") === 0) {
          return origin;
        }
        if (origin === "pino/file") {
          return join(__dirname, "..", "file.js");
        }
        let fixTarget2;
        for (const filePath of callers) {
          try {
            const context = filePath === "node:repl" ? process.cwd() + sep : filePath;
            fixTarget2 = createRequire(context).resolve(origin);
            break;
          } catch (err) {
            continue;
          }
        }
        if (!fixTarget2) {
          throw new Error(`unable to determine transport target for "${origin}"`);
        }
        return fixTarget2;
      }
    }
    module2.exports = transport;
  }
});

// ../../node_modules/pino/lib/tools.js
var require_tools = __commonJS({
  "../../node_modules/pino/lib/tools.js"(exports, module2) {
    "use strict";
    var format = require_quick_format_unescaped();
    var { mapHttpRequest, mapHttpResponse } = require_pino_std_serializers();
    var SonicBoom = require_sonic_boom();
    var onExit = require_on_exit_leak_free();
    var {
      lsCacheSym,
      chindingsSym,
      writeSym,
      serializersSym,
      formatOptsSym,
      endSym,
      stringifiersSym,
      stringifySym,
      stringifySafeSym,
      wildcardFirstSym,
      nestedKeySym,
      formattersSym,
      messageKeySym,
      errorKeySym,
      nestedKeyStrSym,
      msgPrefixSym
    } = require_symbols();
    var { isMainThread } = require("worker_threads");
    var transport = require_transport();
    function noop() {
    }
    function genLog(level, hook) {
      if (!hook)
        return LOG;
      return function hookWrappedLog(...args) {
        hook.call(this, args, LOG, level);
      };
      function LOG(o, ...n) {
        if (typeof o === "object") {
          let msg = o;
          if (o !== null) {
            if (o.method && o.headers && o.socket) {
              o = mapHttpRequest(o);
            } else if (typeof o.setHeader === "function") {
              o = mapHttpResponse(o);
            }
          }
          let formatParams;
          if (msg === null && n.length === 0) {
            formatParams = [null];
          } else {
            msg = n.shift();
            formatParams = n;
          }
          if (typeof this[msgPrefixSym] === "string" && msg !== void 0 && msg !== null) {
            msg = this[msgPrefixSym] + msg;
          }
          this[writeSym](o, format(msg, formatParams, this[formatOptsSym]), level);
        } else {
          let msg = o === void 0 ? n.shift() : o;
          if (typeof this[msgPrefixSym] === "string" && msg !== void 0 && msg !== null) {
            msg = this[msgPrefixSym] + msg;
          }
          this[writeSym](null, format(msg, n, this[formatOptsSym]), level);
        }
      }
    }
    function asString(str) {
      let result = "";
      let last = 0;
      let found = false;
      let point = 255;
      const l = str.length;
      if (l > 100) {
        return JSON.stringify(str);
      }
      for (var i = 0; i < l && point >= 32; i++) {
        point = str.charCodeAt(i);
        if (point === 34 || point === 92) {
          result += str.slice(last, i) + "\\";
          last = i;
          found = true;
        }
      }
      if (!found) {
        result = str;
      } else {
        result += str.slice(last);
      }
      return point < 32 ? JSON.stringify(str) : '"' + result + '"';
    }
    function asJson(obj, msg, num, time) {
      const stringify2 = this[stringifySym];
      const stringifySafe = this[stringifySafeSym];
      const stringifiers = this[stringifiersSym];
      const end = this[endSym];
      const chindings = this[chindingsSym];
      const serializers = this[serializersSym];
      const formatters = this[formattersSym];
      const messageKey = this[messageKeySym];
      const errorKey = this[errorKeySym];
      let data = this[lsCacheSym][num] + time;
      data = data + chindings;
      let value;
      if (formatters.log) {
        obj = formatters.log(obj);
      }
      const wildcardStringifier = stringifiers[wildcardFirstSym];
      let propStr = "";
      for (const key in obj) {
        value = obj[key];
        if (Object.prototype.hasOwnProperty.call(obj, key) && value !== void 0) {
          if (serializers[key]) {
            value = serializers[key](value);
          } else if (key === errorKey && serializers.err) {
            value = serializers.err(value);
          }
          const stringifier = stringifiers[key] || wildcardStringifier;
          switch (typeof value) {
            case "undefined":
            case "function":
              continue;
            case "number":
              if (Number.isFinite(value) === false) {
                value = null;
              }
            case "boolean":
              if (stringifier)
                value = stringifier(value);
              break;
            case "string":
              value = (stringifier || asString)(value);
              break;
            default:
              value = (stringifier || stringify2)(value, stringifySafe);
          }
          if (value === void 0)
            continue;
          propStr += ',"' + key + '":' + value;
        }
      }
      let msgStr = "";
      if (msg !== void 0) {
        value = serializers[messageKey] ? serializers[messageKey](msg) : msg;
        const stringifier = stringifiers[messageKey] || wildcardStringifier;
        switch (typeof value) {
          case "function":
            break;
          case "number":
            if (Number.isFinite(value) === false) {
              value = null;
            }
          case "boolean":
            if (stringifier)
              value = stringifier(value);
            msgStr = ',"' + messageKey + '":' + value;
            break;
          case "string":
            value = (stringifier || asString)(value);
            msgStr = ',"' + messageKey + '":' + value;
            break;
          default:
            value = (stringifier || stringify2)(value, stringifySafe);
            msgStr = ',"' + messageKey + '":' + value;
        }
      }
      if (this[nestedKeySym] && propStr) {
        return data + this[nestedKeyStrSym] + propStr.slice(1) + "}" + msgStr + end;
      } else {
        return data + propStr + msgStr + end;
      }
    }
    function asChindings(instance, bindings) {
      let value;
      let data = instance[chindingsSym];
      const stringify2 = instance[stringifySym];
      const stringifySafe = instance[stringifySafeSym];
      const stringifiers = instance[stringifiersSym];
      const wildcardStringifier = stringifiers[wildcardFirstSym];
      const serializers = instance[serializersSym];
      const formatter = instance[formattersSym].bindings;
      bindings = formatter(bindings);
      for (const key in bindings) {
        value = bindings[key];
        const valid = key !== "level" && key !== "serializers" && key !== "formatters" && key !== "customLevels" && bindings.hasOwnProperty(key) && value !== void 0;
        if (valid === true) {
          value = serializers[key] ? serializers[key](value) : value;
          value = (stringifiers[key] || wildcardStringifier || stringify2)(value, stringifySafe);
          if (value === void 0)
            continue;
          data += ',"' + key + '":' + value;
        }
      }
      return data;
    }
    function hasBeenTampered(stream) {
      return stream.write !== stream.constructor.prototype.write;
    }
    function buildSafeSonicBoom(opts) {
      const stream = new SonicBoom(opts);
      stream.on("error", filterBrokenPipe);
      if (!opts.sync && isMainThread) {
        onExit.register(stream, autoEnd);
        stream.on("close", function() {
          onExit.unregister(stream);
        });
      }
      return stream;
      function filterBrokenPipe(err) {
        if (err.code === "EPIPE") {
          stream.write = noop;
          stream.end = noop;
          stream.flushSync = noop;
          stream.destroy = noop;
          return;
        }
        stream.removeListener("error", filterBrokenPipe);
        stream.emit("error", err);
      }
    }
    function autoEnd(stream, eventName) {
      if (stream.destroyed) {
        return;
      }
      if (eventName === "beforeExit") {
        stream.flush();
        stream.on("drain", function() {
          stream.end();
        });
      } else {
        stream.flushSync();
      }
    }
    function createArgsNormalizer(defaultOptions) {
      return function normalizeArgs(instance, caller, opts = {}, stream) {
        if (typeof opts === "string") {
          stream = buildSafeSonicBoom({ dest: opts });
          opts = {};
        } else if (typeof stream === "string") {
          if (opts && opts.transport) {
            throw Error("only one of option.transport or stream can be specified");
          }
          stream = buildSafeSonicBoom({ dest: stream });
        } else if (opts instanceof SonicBoom || opts.writable || opts._writableState) {
          stream = opts;
          opts = {};
        } else if (opts.transport) {
          if (opts.transport instanceof SonicBoom || opts.transport.writable || opts.transport._writableState) {
            throw Error("option.transport do not allow stream, please pass to option directly. e.g. pino(transport)");
          }
          if (opts.transport.targets && opts.transport.targets.length && opts.formatters && typeof opts.formatters.level === "function") {
            throw Error("option.transport.targets do not allow custom level formatters");
          }
          let customLevels;
          if (opts.customLevels) {
            customLevels = opts.useOnlyCustomLevels ? opts.customLevels : Object.assign({}, opts.levels, opts.customLevels);
          }
          stream = transport({ caller, ...opts.transport, levels: customLevels });
        }
        opts = Object.assign({}, defaultOptions, opts);
        opts.serializers = Object.assign({}, defaultOptions.serializers, opts.serializers);
        opts.formatters = Object.assign({}, defaultOptions.formatters, opts.formatters);
        if (opts.prettyPrint) {
          throw new Error("prettyPrint option is no longer supported, see the pino-pretty package (https://github.com/pinojs/pino-pretty)");
        }
        const { enabled, onChild } = opts;
        if (enabled === false)
          opts.level = "silent";
        if (!onChild)
          opts.onChild = noop;
        if (!stream) {
          if (!hasBeenTampered(process.stdout)) {
            stream = buildSafeSonicBoom({ fd: process.stdout.fd || 1 });
          } else {
            stream = process.stdout;
          }
        }
        return { opts, stream };
      };
    }
    function stringify(obj, stringifySafeFn) {
      try {
        return JSON.stringify(obj);
      } catch (_) {
        try {
          const stringify2 = stringifySafeFn || this[stringifySafeSym];
          return stringify2(obj);
        } catch (_2) {
          return '"[unable to serialize, circular reference is too complex to analyze]"';
        }
      }
    }
    function buildFormatters(level, bindings, log) {
      return {
        level,
        bindings,
        log
      };
    }
    function normalizeDestFileDescriptor(destination) {
      const fd = Number(destination);
      if (typeof destination === "string" && Number.isFinite(fd)) {
        return fd;
      }
      if (destination === void 0) {
        return 1;
      }
      return destination;
    }
    module2.exports = {
      noop,
      buildSafeSonicBoom,
      asChindings,
      asJson,
      genLog,
      createArgsNormalizer,
      stringify,
      buildFormatters,
      normalizeDestFileDescriptor
    };
  }
});

// ../../node_modules/pino/lib/levels.js
var require_levels = __commonJS({
  "../../node_modules/pino/lib/levels.js"(exports, module2) {
    "use strict";
    var {
      lsCacheSym,
      levelValSym,
      useOnlyCustomLevelsSym,
      streamSym,
      formattersSym,
      hooksSym
    } = require_symbols();
    var { noop, genLog } = require_tools();
    var levels = {
      trace: 10,
      debug: 20,
      info: 30,
      warn: 40,
      error: 50,
      fatal: 60
    };
    var levelMethods = {
      fatal: (hook) => {
        const logFatal = genLog(levels.fatal, hook);
        return function(...args) {
          const stream = this[streamSym];
          logFatal.call(this, ...args);
          if (typeof stream.flushSync === "function") {
            try {
              stream.flushSync();
            } catch (e) {
            }
          }
        };
      },
      error: (hook) => genLog(levels.error, hook),
      warn: (hook) => genLog(levels.warn, hook),
      info: (hook) => genLog(levels.info, hook),
      debug: (hook) => genLog(levels.debug, hook),
      trace: (hook) => genLog(levels.trace, hook)
    };
    var nums = Object.keys(levels).reduce((o, k) => {
      o[levels[k]] = k;
      return o;
    }, {});
    var initialLsCache = Object.keys(nums).reduce((o, k) => {
      o[k] = '{"level":' + Number(k);
      return o;
    }, {});
    function genLsCache(instance) {
      const formatter = instance[formattersSym].level;
      const { labels } = instance.levels;
      const cache = {};
      for (const label in labels) {
        const level = formatter(labels[label], Number(label));
        cache[label] = JSON.stringify(level).slice(0, -1);
      }
      instance[lsCacheSym] = cache;
      return instance;
    }
    function isStandardLevel(level, useOnlyCustomLevels) {
      if (useOnlyCustomLevels) {
        return false;
      }
      switch (level) {
        case "fatal":
        case "error":
        case "warn":
        case "info":
        case "debug":
        case "trace":
          return true;
        default:
          return false;
      }
    }
    function setLevel(level) {
      const { labels, values } = this.levels;
      if (typeof level === "number") {
        if (labels[level] === void 0)
          throw Error("unknown level value" + level);
        level = labels[level];
      }
      if (values[level] === void 0)
        throw Error("unknown level " + level);
      const preLevelVal = this[levelValSym];
      const levelVal = this[levelValSym] = values[level];
      const useOnlyCustomLevelsVal = this[useOnlyCustomLevelsSym];
      const hook = this[hooksSym].logMethod;
      for (const key in values) {
        if (levelVal > values[key]) {
          this[key] = noop;
          continue;
        }
        this[key] = isStandardLevel(key, useOnlyCustomLevelsVal) ? levelMethods[key](hook) : genLog(values[key], hook);
      }
      this.emit(
        "level-change",
        level,
        levelVal,
        labels[preLevelVal],
        preLevelVal,
        this
      );
    }
    function getLevel(level) {
      const { levels: levels2, levelVal } = this;
      return levels2 && levels2.labels ? levels2.labels[levelVal] : "";
    }
    function isLevelEnabled(logLevel) {
      const { values } = this.levels;
      const logLevelVal = values[logLevel];
      return logLevelVal !== void 0 && logLevelVal >= this[levelValSym];
    }
    function mappings(customLevels = null, useOnlyCustomLevels = false) {
      const customNums = customLevels ? Object.keys(customLevels).reduce((o, k) => {
        o[customLevels[k]] = k;
        return o;
      }, {}) : null;
      const labels = Object.assign(
        Object.create(Object.prototype, { Infinity: { value: "silent" } }),
        useOnlyCustomLevels ? null : nums,
        customNums
      );
      const values = Object.assign(
        Object.create(Object.prototype, { silent: { value: Infinity } }),
        useOnlyCustomLevels ? null : levels,
        customLevels
      );
      return { labels, values };
    }
    function assertDefaultLevelFound(defaultLevel, customLevels, useOnlyCustomLevels) {
      if (typeof defaultLevel === "number") {
        const values = [].concat(
          Object.keys(customLevels || {}).map((key) => customLevels[key]),
          useOnlyCustomLevels ? [] : Object.keys(nums).map((level) => +level),
          Infinity
        );
        if (!values.includes(defaultLevel)) {
          throw Error(`default level:${defaultLevel} must be included in custom levels`);
        }
        return;
      }
      const labels = Object.assign(
        Object.create(Object.prototype, { silent: { value: Infinity } }),
        useOnlyCustomLevels ? null : levels,
        customLevels
      );
      if (!(defaultLevel in labels)) {
        throw Error(`default level:${defaultLevel} must be included in custom levels`);
      }
    }
    function assertNoLevelCollisions(levels2, customLevels) {
      const { labels, values } = levels2;
      for (const k in customLevels) {
        if (k in values) {
          throw Error("levels cannot be overridden");
        }
        if (customLevels[k] in labels) {
          throw Error("pre-existing level values cannot be used for new levels");
        }
      }
    }
    module2.exports = {
      initialLsCache,
      genLsCache,
      levelMethods,
      getLevel,
      setLevel,
      isLevelEnabled,
      mappings,
      levels,
      assertNoLevelCollisions,
      assertDefaultLevelFound
    };
  }
});

// ../../node_modules/pino/lib/meta.js
var require_meta = __commonJS({
  "../../node_modules/pino/lib/meta.js"(exports, module2) {
    "use strict";
    module2.exports = { version: "8.14.2" };
  }
});

// ../../node_modules/pino/lib/proto.js
var require_proto = __commonJS({
  "../../node_modules/pino/lib/proto.js"(exports, module2) {
    "use strict";
    var { EventEmitter } = require("events");
    var {
      lsCacheSym,
      levelValSym,
      setLevelSym,
      getLevelSym,
      chindingsSym,
      parsedChindingsSym,
      mixinSym,
      asJsonSym,
      writeSym,
      mixinMergeStrategySym,
      timeSym,
      timeSliceIndexSym,
      streamSym,
      serializersSym,
      formattersSym,
      errorKeySym,
      messageKeySym,
      useOnlyCustomLevelsSym,
      needsMetadataGsym,
      redactFmtSym,
      stringifySym,
      formatOptsSym,
      stringifiersSym,
      msgPrefixSym
    } = require_symbols();
    var {
      getLevel,
      setLevel,
      isLevelEnabled,
      mappings,
      initialLsCache,
      genLsCache,
      assertNoLevelCollisions
    } = require_levels();
    var {
      asChindings,
      asJson,
      buildFormatters,
      stringify
    } = require_tools();
    var {
      version
    } = require_meta();
    var redaction = require_redaction();
    var constructor = class Pino {
    };
    var prototype = {
      constructor,
      child,
      bindings,
      setBindings,
      flush,
      isLevelEnabled,
      version,
      get level() {
        return this[getLevelSym]();
      },
      set level(lvl) {
        this[setLevelSym](lvl);
      },
      get levelVal() {
        return this[levelValSym];
      },
      set levelVal(n) {
        throw Error("levelVal is read-only");
      },
      [lsCacheSym]: initialLsCache,
      [writeSym]: write,
      [asJsonSym]: asJson,
      [getLevelSym]: getLevel,
      [setLevelSym]: setLevel
    };
    Object.setPrototypeOf(prototype, EventEmitter.prototype);
    module2.exports = function() {
      return Object.create(prototype);
    };
    var resetChildingsFormatter = (bindings2) => bindings2;
    function child(bindings2, options) {
      if (!bindings2) {
        throw Error("missing bindings for child Pino");
      }
      options = options || {};
      const serializers = this[serializersSym];
      const formatters = this[formattersSym];
      const instance = Object.create(this);
      if (options.hasOwnProperty("serializers") === true) {
        instance[serializersSym] = /* @__PURE__ */ Object.create(null);
        for (const k in serializers) {
          instance[serializersSym][k] = serializers[k];
        }
        const parentSymbols = Object.getOwnPropertySymbols(serializers);
        for (var i = 0; i < parentSymbols.length; i++) {
          const ks = parentSymbols[i];
          instance[serializersSym][ks] = serializers[ks];
        }
        for (const bk in options.serializers) {
          instance[serializersSym][bk] = options.serializers[bk];
        }
        const bindingsSymbols = Object.getOwnPropertySymbols(options.serializers);
        for (var bi = 0; bi < bindingsSymbols.length; bi++) {
          const bks = bindingsSymbols[bi];
          instance[serializersSym][bks] = options.serializers[bks];
        }
      } else
        instance[serializersSym] = serializers;
      if (options.hasOwnProperty("formatters")) {
        const { level, bindings: chindings, log } = options.formatters;
        instance[formattersSym] = buildFormatters(
          level || formatters.level,
          chindings || resetChildingsFormatter,
          log || formatters.log
        );
      } else {
        instance[formattersSym] = buildFormatters(
          formatters.level,
          resetChildingsFormatter,
          formatters.log
        );
      }
      if (options.hasOwnProperty("customLevels") === true) {
        assertNoLevelCollisions(this.levels, options.customLevels);
        instance.levels = mappings(options.customLevels, instance[useOnlyCustomLevelsSym]);
        genLsCache(instance);
      }
      if (typeof options.redact === "object" && options.redact !== null || Array.isArray(options.redact)) {
        instance.redact = options.redact;
        const stringifiers = redaction(instance.redact, stringify);
        const formatOpts = { stringify: stringifiers[redactFmtSym] };
        instance[stringifySym] = stringify;
        instance[stringifiersSym] = stringifiers;
        instance[formatOptsSym] = formatOpts;
      }
      if (typeof options.msgPrefix === "string") {
        instance[msgPrefixSym] = (this[msgPrefixSym] || "") + options.msgPrefix;
      }
      instance[chindingsSym] = asChindings(instance, bindings2);
      const childLevel = options.level || this.level;
      instance[setLevelSym](childLevel);
      this.onChild(instance);
      return instance;
    }
    function bindings() {
      const chindings = this[chindingsSym];
      const chindingsJson = `{${chindings.substr(1)}}`;
      const bindingsFromJson = JSON.parse(chindingsJson);
      delete bindingsFromJson.pid;
      delete bindingsFromJson.hostname;
      return bindingsFromJson;
    }
    function setBindings(newBindings) {
      const chindings = asChindings(this, newBindings);
      this[chindingsSym] = chindings;
      delete this[parsedChindingsSym];
    }
    function defaultMixinMergeStrategy(mergeObject, mixinObject) {
      return Object.assign(mixinObject, mergeObject);
    }
    function write(_obj, msg, num) {
      const t = this[timeSym]();
      const mixin = this[mixinSym];
      const errorKey = this[errorKeySym];
      const messageKey = this[messageKeySym];
      const mixinMergeStrategy = this[mixinMergeStrategySym] || defaultMixinMergeStrategy;
      let obj;
      if (_obj === void 0 || _obj === null) {
        obj = {};
      } else if (_obj instanceof Error) {
        obj = { [errorKey]: _obj };
        if (msg === void 0) {
          msg = _obj.message;
        }
      } else {
        obj = _obj;
        if (msg === void 0 && _obj[messageKey] === void 0 && _obj[errorKey]) {
          msg = _obj[errorKey].message;
        }
      }
      if (mixin) {
        obj = mixinMergeStrategy(obj, mixin(obj, num, this));
      }
      const s = this[asJsonSym](obj, msg, num, t);
      const stream = this[streamSym];
      if (stream[needsMetadataGsym] === true) {
        stream.lastLevel = num;
        stream.lastObj = obj;
        stream.lastMsg = msg;
        stream.lastTime = t.slice(this[timeSliceIndexSym]);
        stream.lastLogger = this;
      }
      stream.write(s);
    }
    function noop() {
    }
    function flush() {
      const stream = this[streamSym];
      if ("flush" in stream)
        stream.flush(noop);
    }
  }
});

// ../../node_modules/safe-stable-stringify/index.js
var require_safe_stable_stringify = __commonJS({
  "../../node_modules/safe-stable-stringify/index.js"(exports, module2) {
    "use strict";
    var { hasOwnProperty } = Object.prototype;
    var stringify = configure();
    stringify.configure = configure;
    stringify.stringify = stringify;
    stringify.default = stringify;
    exports.stringify = stringify;
    exports.configure = configure;
    module2.exports = stringify;
    var strEscapeSequencesRegExp = /[\u0000-\u001f\u0022\u005c\ud800-\udfff]|[\ud800-\udbff](?![\udc00-\udfff])|(?:[^\ud800-\udbff]|^)[\udc00-\udfff]/;
    function strEscape(str) {
      if (str.length < 5e3 && !strEscapeSequencesRegExp.test(str)) {
        return `"${str}"`;
      }
      return JSON.stringify(str);
    }
    function insertSort(array) {
      if (array.length > 200) {
        return array.sort();
      }
      for (let i = 1; i < array.length; i++) {
        const currentValue = array[i];
        let position = i;
        while (position !== 0 && array[position - 1] > currentValue) {
          array[position] = array[position - 1];
          position--;
        }
        array[position] = currentValue;
      }
      return array;
    }
    var typedArrayPrototypeGetSymbolToStringTag = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(
        Object.getPrototypeOf(
          new Int8Array()
        )
      ),
      Symbol.toStringTag
    ).get;
    function isTypedArrayWithEntries(value) {
      return typedArrayPrototypeGetSymbolToStringTag.call(value) !== void 0 && value.length !== 0;
    }
    function stringifyTypedArray(array, separator, maximumBreadth) {
      if (array.length < maximumBreadth) {
        maximumBreadth = array.length;
      }
      const whitespace = separator === "," ? "" : " ";
      let res = `"0":${whitespace}${array[0]}`;
      for (let i = 1; i < maximumBreadth; i++) {
        res += `${separator}"${i}":${whitespace}${array[i]}`;
      }
      return res;
    }
    function getCircularValueOption(options) {
      if (hasOwnProperty.call(options, "circularValue")) {
        const circularValue = options.circularValue;
        if (typeof circularValue === "string") {
          return `"${circularValue}"`;
        }
        if (circularValue == null) {
          return circularValue;
        }
        if (circularValue === Error || circularValue === TypeError) {
          return {
            toString() {
              throw new TypeError("Converting circular structure to JSON");
            }
          };
        }
        throw new TypeError('The "circularValue" argument must be of type string or the value null or undefined');
      }
      return '"[Circular]"';
    }
    function getBooleanOption(options, key) {
      let value;
      if (hasOwnProperty.call(options, key)) {
        value = options[key];
        if (typeof value !== "boolean") {
          throw new TypeError(`The "${key}" argument must be of type boolean`);
        }
      }
      return value === void 0 ? true : value;
    }
    function getPositiveIntegerOption(options, key) {
      let value;
      if (hasOwnProperty.call(options, key)) {
        value = options[key];
        if (typeof value !== "number") {
          throw new TypeError(`The "${key}" argument must be of type number`);
        }
        if (!Number.isInteger(value)) {
          throw new TypeError(`The "${key}" argument must be an integer`);
        }
        if (value < 1) {
          throw new RangeError(`The "${key}" argument must be >= 1`);
        }
      }
      return value === void 0 ? Infinity : value;
    }
    function getItemCount(number) {
      if (number === 1) {
        return "1 item";
      }
      return `${number} items`;
    }
    function getUniqueReplacerSet(replacerArray) {
      const replacerSet = /* @__PURE__ */ new Set();
      for (const value of replacerArray) {
        if (typeof value === "string" || typeof value === "number") {
          replacerSet.add(String(value));
        }
      }
      return replacerSet;
    }
    function getStrictOption(options) {
      if (hasOwnProperty.call(options, "strict")) {
        const value = options.strict;
        if (typeof value !== "boolean") {
          throw new TypeError('The "strict" argument must be of type boolean');
        }
        if (value) {
          return (value2) => {
            let message = `Object can not safely be stringified. Received type ${typeof value2}`;
            if (typeof value2 !== "function")
              message += ` (${value2.toString()})`;
            throw new Error(message);
          };
        }
      }
    }
    function configure(options) {
      options = { ...options };
      const fail = getStrictOption(options);
      if (fail) {
        if (options.bigint === void 0) {
          options.bigint = false;
        }
        if (!("circularValue" in options)) {
          options.circularValue = Error;
        }
      }
      const circularValue = getCircularValueOption(options);
      const bigint = getBooleanOption(options, "bigint");
      const deterministic = getBooleanOption(options, "deterministic");
      const maximumDepth = getPositiveIntegerOption(options, "maximumDepth");
      const maximumBreadth = getPositiveIntegerOption(options, "maximumBreadth");
      function stringifyFnReplacer(key, parent, stack, replacer, spacer, indentation) {
        let value = parent[key];
        if (typeof value === "object" && value !== null && typeof value.toJSON === "function") {
          value = value.toJSON(key);
        }
        value = replacer.call(parent, key, value);
        switch (typeof value) {
          case "string":
            return strEscape(value);
          case "object": {
            if (value === null) {
              return "null";
            }
            if (stack.indexOf(value) !== -1) {
              return circularValue;
            }
            let res = "";
            let join = ",";
            const originalIndentation = indentation;
            if (Array.isArray(value)) {
              if (value.length === 0) {
                return "[]";
              }
              if (maximumDepth < stack.length + 1) {
                return '"[Array]"';
              }
              stack.push(value);
              if (spacer !== "") {
                indentation += spacer;
                res += `
${indentation}`;
                join = `,
${indentation}`;
              }
              const maximumValuesToStringify = Math.min(value.length, maximumBreadth);
              let i = 0;
              for (; i < maximumValuesToStringify - 1; i++) {
                const tmp2 = stringifyFnReplacer(String(i), value, stack, replacer, spacer, indentation);
                res += tmp2 !== void 0 ? tmp2 : "null";
                res += join;
              }
              const tmp = stringifyFnReplacer(String(i), value, stack, replacer, spacer, indentation);
              res += tmp !== void 0 ? tmp : "null";
              if (value.length - 1 > maximumBreadth) {
                const removedKeys = value.length - maximumBreadth - 1;
                res += `${join}"... ${getItemCount(removedKeys)} not stringified"`;
              }
              if (spacer !== "") {
                res += `
${originalIndentation}`;
              }
              stack.pop();
              return `[${res}]`;
            }
            let keys = Object.keys(value);
            const keyLength = keys.length;
            if (keyLength === 0) {
              return "{}";
            }
            if (maximumDepth < stack.length + 1) {
              return '"[Object]"';
            }
            let whitespace = "";
            let separator = "";
            if (spacer !== "") {
              indentation += spacer;
              join = `,
${indentation}`;
              whitespace = " ";
            }
            const maximumPropertiesToStringify = Math.min(keyLength, maximumBreadth);
            if (deterministic && !isTypedArrayWithEntries(value)) {
              keys = insertSort(keys);
            }
            stack.push(value);
            for (let i = 0; i < maximumPropertiesToStringify; i++) {
              const key2 = keys[i];
              const tmp = stringifyFnReplacer(key2, value, stack, replacer, spacer, indentation);
              if (tmp !== void 0) {
                res += `${separator}${strEscape(key2)}:${whitespace}${tmp}`;
                separator = join;
              }
            }
            if (keyLength > maximumBreadth) {
              const removedKeys = keyLength - maximumBreadth;
              res += `${separator}"...":${whitespace}"${getItemCount(removedKeys)} not stringified"`;
              separator = join;
            }
            if (spacer !== "" && separator.length > 1) {
              res = `
${indentation}${res}
${originalIndentation}`;
            }
            stack.pop();
            return `{${res}}`;
          }
          case "number":
            return isFinite(value) ? String(value) : fail ? fail(value) : "null";
          case "boolean":
            return value === true ? "true" : "false";
          case "undefined":
            return void 0;
          case "bigint":
            if (bigint) {
              return String(value);
            }
          default:
            return fail ? fail(value) : void 0;
        }
      }
      function stringifyArrayReplacer(key, value, stack, replacer, spacer, indentation) {
        if (typeof value === "object" && value !== null && typeof value.toJSON === "function") {
          value = value.toJSON(key);
        }
        switch (typeof value) {
          case "string":
            return strEscape(value);
          case "object": {
            if (value === null) {
              return "null";
            }
            if (stack.indexOf(value) !== -1) {
              return circularValue;
            }
            const originalIndentation = indentation;
            let res = "";
            let join = ",";
            if (Array.isArray(value)) {
              if (value.length === 0) {
                return "[]";
              }
              if (maximumDepth < stack.length + 1) {
                return '"[Array]"';
              }
              stack.push(value);
              if (spacer !== "") {
                indentation += spacer;
                res += `
${indentation}`;
                join = `,
${indentation}`;
              }
              const maximumValuesToStringify = Math.min(value.length, maximumBreadth);
              let i = 0;
              for (; i < maximumValuesToStringify - 1; i++) {
                const tmp2 = stringifyArrayReplacer(String(i), value[i], stack, replacer, spacer, indentation);
                res += tmp2 !== void 0 ? tmp2 : "null";
                res += join;
              }
              const tmp = stringifyArrayReplacer(String(i), value[i], stack, replacer, spacer, indentation);
              res += tmp !== void 0 ? tmp : "null";
              if (value.length - 1 > maximumBreadth) {
                const removedKeys = value.length - maximumBreadth - 1;
                res += `${join}"... ${getItemCount(removedKeys)} not stringified"`;
              }
              if (spacer !== "") {
                res += `
${originalIndentation}`;
              }
              stack.pop();
              return `[${res}]`;
            }
            stack.push(value);
            let whitespace = "";
            if (spacer !== "") {
              indentation += spacer;
              join = `,
${indentation}`;
              whitespace = " ";
            }
            let separator = "";
            for (const key2 of replacer) {
              const tmp = stringifyArrayReplacer(key2, value[key2], stack, replacer, spacer, indentation);
              if (tmp !== void 0) {
                res += `${separator}${strEscape(key2)}:${whitespace}${tmp}`;
                separator = join;
              }
            }
            if (spacer !== "" && separator.length > 1) {
              res = `
${indentation}${res}
${originalIndentation}`;
            }
            stack.pop();
            return `{${res}}`;
          }
          case "number":
            return isFinite(value) ? String(value) : fail ? fail(value) : "null";
          case "boolean":
            return value === true ? "true" : "false";
          case "undefined":
            return void 0;
          case "bigint":
            if (bigint) {
              return String(value);
            }
          default:
            return fail ? fail(value) : void 0;
        }
      }
      function stringifyIndent(key, value, stack, spacer, indentation) {
        switch (typeof value) {
          case "string":
            return strEscape(value);
          case "object": {
            if (value === null) {
              return "null";
            }
            if (typeof value.toJSON === "function") {
              value = value.toJSON(key);
              if (typeof value !== "object") {
                return stringifyIndent(key, value, stack, spacer, indentation);
              }
              if (value === null) {
                return "null";
              }
            }
            if (stack.indexOf(value) !== -1) {
              return circularValue;
            }
            const originalIndentation = indentation;
            if (Array.isArray(value)) {
              if (value.length === 0) {
                return "[]";
              }
              if (maximumDepth < stack.length + 1) {
                return '"[Array]"';
              }
              stack.push(value);
              indentation += spacer;
              let res2 = `
${indentation}`;
              const join2 = `,
${indentation}`;
              const maximumValuesToStringify = Math.min(value.length, maximumBreadth);
              let i = 0;
              for (; i < maximumValuesToStringify - 1; i++) {
                const tmp2 = stringifyIndent(String(i), value[i], stack, spacer, indentation);
                res2 += tmp2 !== void 0 ? tmp2 : "null";
                res2 += join2;
              }
              const tmp = stringifyIndent(String(i), value[i], stack, spacer, indentation);
              res2 += tmp !== void 0 ? tmp : "null";
              if (value.length - 1 > maximumBreadth) {
                const removedKeys = value.length - maximumBreadth - 1;
                res2 += `${join2}"... ${getItemCount(removedKeys)} not stringified"`;
              }
              res2 += `
${originalIndentation}`;
              stack.pop();
              return `[${res2}]`;
            }
            let keys = Object.keys(value);
            const keyLength = keys.length;
            if (keyLength === 0) {
              return "{}";
            }
            if (maximumDepth < stack.length + 1) {
              return '"[Object]"';
            }
            indentation += spacer;
            const join = `,
${indentation}`;
            let res = "";
            let separator = "";
            let maximumPropertiesToStringify = Math.min(keyLength, maximumBreadth);
            if (isTypedArrayWithEntries(value)) {
              res += stringifyTypedArray(value, join, maximumBreadth);
              keys = keys.slice(value.length);
              maximumPropertiesToStringify -= value.length;
              separator = join;
            }
            if (deterministic) {
              keys = insertSort(keys);
            }
            stack.push(value);
            for (let i = 0; i < maximumPropertiesToStringify; i++) {
              const key2 = keys[i];
              const tmp = stringifyIndent(key2, value[key2], stack, spacer, indentation);
              if (tmp !== void 0) {
                res += `${separator}${strEscape(key2)}: ${tmp}`;
                separator = join;
              }
            }
            if (keyLength > maximumBreadth) {
              const removedKeys = keyLength - maximumBreadth;
              res += `${separator}"...": "${getItemCount(removedKeys)} not stringified"`;
              separator = join;
            }
            if (separator !== "") {
              res = `
${indentation}${res}
${originalIndentation}`;
            }
            stack.pop();
            return `{${res}}`;
          }
          case "number":
            return isFinite(value) ? String(value) : fail ? fail(value) : "null";
          case "boolean":
            return value === true ? "true" : "false";
          case "undefined":
            return void 0;
          case "bigint":
            if (bigint) {
              return String(value);
            }
          default:
            return fail ? fail(value) : void 0;
        }
      }
      function stringifySimple(key, value, stack) {
        switch (typeof value) {
          case "string":
            return strEscape(value);
          case "object": {
            if (value === null) {
              return "null";
            }
            if (typeof value.toJSON === "function") {
              value = value.toJSON(key);
              if (typeof value !== "object") {
                return stringifySimple(key, value, stack);
              }
              if (value === null) {
                return "null";
              }
            }
            if (stack.indexOf(value) !== -1) {
              return circularValue;
            }
            let res = "";
            if (Array.isArray(value)) {
              if (value.length === 0) {
                return "[]";
              }
              if (maximumDepth < stack.length + 1) {
                return '"[Array]"';
              }
              stack.push(value);
              const maximumValuesToStringify = Math.min(value.length, maximumBreadth);
              let i = 0;
              for (; i < maximumValuesToStringify - 1; i++) {
                const tmp2 = stringifySimple(String(i), value[i], stack);
                res += tmp2 !== void 0 ? tmp2 : "null";
                res += ",";
              }
              const tmp = stringifySimple(String(i), value[i], stack);
              res += tmp !== void 0 ? tmp : "null";
              if (value.length - 1 > maximumBreadth) {
                const removedKeys = value.length - maximumBreadth - 1;
                res += `,"... ${getItemCount(removedKeys)} not stringified"`;
              }
              stack.pop();
              return `[${res}]`;
            }
            let keys = Object.keys(value);
            const keyLength = keys.length;
            if (keyLength === 0) {
              return "{}";
            }
            if (maximumDepth < stack.length + 1) {
              return '"[Object]"';
            }
            let separator = "";
            let maximumPropertiesToStringify = Math.min(keyLength, maximumBreadth);
            if (isTypedArrayWithEntries(value)) {
              res += stringifyTypedArray(value, ",", maximumBreadth);
              keys = keys.slice(value.length);
              maximumPropertiesToStringify -= value.length;
              separator = ",";
            }
            if (deterministic) {
              keys = insertSort(keys);
            }
            stack.push(value);
            for (let i = 0; i < maximumPropertiesToStringify; i++) {
              const key2 = keys[i];
              const tmp = stringifySimple(key2, value[key2], stack);
              if (tmp !== void 0) {
                res += `${separator}${strEscape(key2)}:${tmp}`;
                separator = ",";
              }
            }
            if (keyLength > maximumBreadth) {
              const removedKeys = keyLength - maximumBreadth;
              res += `${separator}"...":"${getItemCount(removedKeys)} not stringified"`;
            }
            stack.pop();
            return `{${res}}`;
          }
          case "number":
            return isFinite(value) ? String(value) : fail ? fail(value) : "null";
          case "boolean":
            return value === true ? "true" : "false";
          case "undefined":
            return void 0;
          case "bigint":
            if (bigint) {
              return String(value);
            }
          default:
            return fail ? fail(value) : void 0;
        }
      }
      function stringify2(value, replacer, space) {
        if (arguments.length > 1) {
          let spacer = "";
          if (typeof space === "number") {
            spacer = " ".repeat(Math.min(space, 10));
          } else if (typeof space === "string") {
            spacer = space.slice(0, 10);
          }
          if (replacer != null) {
            if (typeof replacer === "function") {
              return stringifyFnReplacer("", { "": value }, [], replacer, spacer, "");
            }
            if (Array.isArray(replacer)) {
              return stringifyArrayReplacer("", value, [], getUniqueReplacerSet(replacer), spacer, "");
            }
          }
          if (spacer.length !== 0) {
            return stringifyIndent("", value, [], spacer, "");
          }
        }
        return stringifySimple("", value, []);
      }
      return stringify2;
    }
  }
});

// ../../node_modules/pino/lib/multistream.js
var require_multistream = __commonJS({
  "../../node_modules/pino/lib/multistream.js"(exports, module2) {
    "use strict";
    var metadata = Symbol.for("pino.metadata");
    var { levels } = require_levels();
    var defaultLevels = Object.create(levels);
    defaultLevels.silent = Infinity;
    var DEFAULT_INFO_LEVEL = levels.info;
    function multistream(streamsArray, opts) {
      let counter = 0;
      streamsArray = streamsArray || [];
      opts = opts || { dedupe: false };
      let levels2 = defaultLevels;
      if (opts.levels && typeof opts.levels === "object") {
        levels2 = opts.levels;
      }
      const res = {
        write,
        add,
        flushSync,
        end,
        minLevel: 0,
        streams: [],
        clone,
        [metadata]: true
      };
      if (Array.isArray(streamsArray)) {
        streamsArray.forEach(add, res);
      } else {
        add.call(res, streamsArray);
      }
      streamsArray = null;
      return res;
      function write(data) {
        let dest;
        const level = this.lastLevel;
        const { streams } = this;
        let recordedLevel = 0;
        let stream;
        for (let i = initLoopVar(streams.length, opts.dedupe); checkLoopVar(i, streams.length, opts.dedupe); i = adjustLoopVar(i, opts.dedupe)) {
          dest = streams[i];
          if (dest.level <= level) {
            if (recordedLevel !== 0 && recordedLevel !== dest.level) {
              break;
            }
            stream = dest.stream;
            if (stream[metadata]) {
              const { lastTime, lastMsg, lastObj, lastLogger } = this;
              stream.lastLevel = level;
              stream.lastTime = lastTime;
              stream.lastMsg = lastMsg;
              stream.lastObj = lastObj;
              stream.lastLogger = lastLogger;
            }
            stream.write(data);
            if (opts.dedupe) {
              recordedLevel = dest.level;
            }
          } else if (!opts.dedupe) {
            break;
          }
        }
      }
      function flushSync() {
        for (const { stream } of this.streams) {
          if (typeof stream.flushSync === "function") {
            stream.flushSync();
          }
        }
      }
      function add(dest) {
        if (!dest) {
          return res;
        }
        const isStream = typeof dest.write === "function" || dest.stream;
        const stream_ = dest.write ? dest : dest.stream;
        if (!isStream) {
          throw Error("stream object needs to implement either StreamEntry or DestinationStream interface");
        }
        const { streams } = this;
        let level;
        if (typeof dest.levelVal === "number") {
          level = dest.levelVal;
        } else if (typeof dest.level === "string") {
          level = levels2[dest.level];
        } else if (typeof dest.level === "number") {
          level = dest.level;
        } else {
          level = DEFAULT_INFO_LEVEL;
        }
        const dest_ = {
          stream: stream_,
          level,
          levelVal: void 0,
          id: counter++
        };
        streams.unshift(dest_);
        streams.sort(compareByLevel);
        this.minLevel = streams[0].level;
        return res;
      }
      function end() {
        for (const { stream } of this.streams) {
          if (typeof stream.flushSync === "function") {
            stream.flushSync();
          }
          stream.end();
        }
      }
      function clone(level) {
        const streams = new Array(this.streams.length);
        for (let i = 0; i < streams.length; i++) {
          streams[i] = {
            level,
            stream: this.streams[i].stream
          };
        }
        return {
          write,
          add,
          minLevel: level,
          streams,
          clone,
          flushSync,
          [metadata]: true
        };
      }
    }
    function compareByLevel(a, b) {
      return a.level - b.level;
    }
    function initLoopVar(length, dedupe) {
      return dedupe ? length - 1 : 0;
    }
    function adjustLoopVar(i, dedupe) {
      return dedupe ? i - 1 : i + 1;
    }
    function checkLoopVar(i, length, dedupe) {
      return dedupe ? i >= 0 : i < length;
    }
    module2.exports = multistream;
  }
});

// ../../node_modules/pino/pino.js
var require_pino = __commonJS({
  "../../node_modules/pino/pino.js"(exports, module2) {
    "use strict";
    var os = require("os");
    var stdSerializers = require_pino_std_serializers();
    var caller = require_caller();
    var redaction = require_redaction();
    var time = require_time();
    var proto = require_proto();
    var symbols = require_symbols();
    var { configure } = require_safe_stable_stringify();
    var { assertDefaultLevelFound, mappings, genLsCache, levels } = require_levels();
    var {
      createArgsNormalizer,
      asChindings,
      buildSafeSonicBoom,
      buildFormatters,
      stringify,
      normalizeDestFileDescriptor,
      noop
    } = require_tools();
    var { version } = require_meta();
    var {
      chindingsSym,
      redactFmtSym,
      serializersSym,
      timeSym,
      timeSliceIndexSym,
      streamSym,
      stringifySym,
      stringifySafeSym,
      stringifiersSym,
      setLevelSym,
      endSym,
      formatOptsSym,
      messageKeySym,
      errorKeySym,
      nestedKeySym,
      mixinSym,
      useOnlyCustomLevelsSym,
      formattersSym,
      hooksSym,
      nestedKeyStrSym,
      mixinMergeStrategySym,
      msgPrefixSym
    } = symbols;
    var { epochTime, nullTime } = time;
    var { pid } = process;
    var hostname = os.hostname();
    var defaultErrorSerializer = stdSerializers.err;
    var defaultOptions = {
      level: "info",
      levels,
      messageKey: "msg",
      errorKey: "err",
      nestedKey: null,
      enabled: true,
      base: { pid, hostname },
      serializers: Object.assign(/* @__PURE__ */ Object.create(null), {
        err: defaultErrorSerializer
      }),
      formatters: Object.assign(/* @__PURE__ */ Object.create(null), {
        bindings(bindings) {
          return bindings;
        },
        level(label, number) {
          return { level: number };
        }
      }),
      hooks: {
        logMethod: void 0
      },
      timestamp: epochTime,
      name: void 0,
      redact: null,
      customLevels: null,
      useOnlyCustomLevels: false,
      depthLimit: 5,
      edgeLimit: 100
    };
    var normalize = createArgsNormalizer(defaultOptions);
    var serializers = Object.assign(/* @__PURE__ */ Object.create(null), stdSerializers);
    function pino(...args) {
      const instance = {};
      const { opts, stream } = normalize(instance, caller(), ...args);
      const {
        redact,
        crlf,
        serializers: serializers2,
        timestamp,
        messageKey,
        errorKey,
        nestedKey,
        base,
        name,
        level,
        customLevels,
        mixin,
        mixinMergeStrategy,
        useOnlyCustomLevels,
        formatters,
        hooks,
        depthLimit,
        edgeLimit,
        onChild,
        msgPrefix
      } = opts;
      const stringifySafe = configure({
        maximumDepth: depthLimit,
        maximumBreadth: edgeLimit
      });
      const allFormatters = buildFormatters(
        formatters.level,
        formatters.bindings,
        formatters.log
      );
      const stringifyFn = stringify.bind({
        [stringifySafeSym]: stringifySafe
      });
      const stringifiers = redact ? redaction(redact, stringifyFn) : {};
      const formatOpts = redact ? { stringify: stringifiers[redactFmtSym] } : { stringify: stringifyFn };
      const end = "}" + (crlf ? "\r\n" : "\n");
      const coreChindings = asChindings.bind(null, {
        [chindingsSym]: "",
        [serializersSym]: serializers2,
        [stringifiersSym]: stringifiers,
        [stringifySym]: stringify,
        [stringifySafeSym]: stringifySafe,
        [formattersSym]: allFormatters
      });
      let chindings = "";
      if (base !== null) {
        if (name === void 0) {
          chindings = coreChindings(base);
        } else {
          chindings = coreChindings(Object.assign({}, base, { name }));
        }
      }
      const time2 = timestamp instanceof Function ? timestamp : timestamp ? epochTime : nullTime;
      const timeSliceIndex = time2().indexOf(":") + 1;
      if (useOnlyCustomLevels && !customLevels)
        throw Error("customLevels is required if useOnlyCustomLevels is set true");
      if (mixin && typeof mixin !== "function")
        throw Error(`Unknown mixin type "${typeof mixin}" - expected "function"`);
      if (msgPrefix && typeof msgPrefix !== "string")
        throw Error(`Unknown msgPrefix type "${typeof msgPrefix}" - expected "string"`);
      assertDefaultLevelFound(level, customLevels, useOnlyCustomLevels);
      const levels2 = mappings(customLevels, useOnlyCustomLevels);
      Object.assign(instance, {
        levels: levels2,
        [useOnlyCustomLevelsSym]: useOnlyCustomLevels,
        [streamSym]: stream,
        [timeSym]: time2,
        [timeSliceIndexSym]: timeSliceIndex,
        [stringifySym]: stringify,
        [stringifySafeSym]: stringifySafe,
        [stringifiersSym]: stringifiers,
        [endSym]: end,
        [formatOptsSym]: formatOpts,
        [messageKeySym]: messageKey,
        [errorKeySym]: errorKey,
        [nestedKeySym]: nestedKey,
        // protect against injection
        [nestedKeyStrSym]: nestedKey ? `,${JSON.stringify(nestedKey)}:{` : "",
        [serializersSym]: serializers2,
        [mixinSym]: mixin,
        [mixinMergeStrategySym]: mixinMergeStrategy,
        [chindingsSym]: chindings,
        [formattersSym]: allFormatters,
        [hooksSym]: hooks,
        silent: noop,
        onChild,
        [msgPrefixSym]: msgPrefix
      });
      Object.setPrototypeOf(instance, proto());
      genLsCache(instance);
      instance[setLevelSym](level);
      return instance;
    }
    module2.exports = pino;
    module2.exports.destination = (dest = process.stdout.fd) => {
      if (typeof dest === "object") {
        dest.dest = normalizeDestFileDescriptor(dest.dest || process.stdout.fd);
        return buildSafeSonicBoom(dest);
      } else {
        return buildSafeSonicBoom({ dest: normalizeDestFileDescriptor(dest), minLength: 0 });
      }
    };
    module2.exports.transport = require_transport();
    module2.exports.multistream = require_multistream();
    module2.exports.levels = mappings();
    module2.exports.stdSerializers = serializers;
    module2.exports.stdTimeFunctions = Object.assign({}, time);
    module2.exports.symbols = symbols;
    module2.exports.version = version;
    module2.exports.default = pino;
    module2.exports.pino = pino;
  }
});

// ../../node_modules/cognito-at-edge/dist/util/cookie.js
var require_cookie = __commonJS({
  "../../node_modules/cognito-at-edge/dist/util/cookie.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getCookieDomain = exports.Cookies = exports.SAME_SITE_VALUES = void 0;
    exports.SAME_SITE_VALUES = ["Strict", "Lax", "None"];
    var Cookies = class {
      /**
       * Parse `Cookie` header string compliant with RFC 6265 and decode URI encoded characters.
       *
       * @param cookiesString 'Cookie' header value
       * @returns array of {@type Cookie} objects
       */
      static parse(cookiesString) {
        const cookieStrArray = cookiesString ? cookiesString.split(";") : [];
        const cookies = [];
        for (const cookieStr of cookieStrArray) {
          const separatorIndex = cookieStr.indexOf("=");
          if (separatorIndex < 0) {
            continue;
          }
          const name = this.decodeName(cookieStr.substring(0, separatorIndex).trim());
          const value = this.decodeValue(cookieStr.substring(separatorIndex + 1).trim());
          cookies.push({ name, value });
        }
        return cookies;
      }
      /**
       * Serialize a cookie name-value pair into a `Set-Cookie` header string and URI encode characters that doesn't comply
       * with RFC 6265
       *
       * @param name cookie name
       * @param value cookie value
       * @param attributes cookie attributes
       * @returns string to be used as `Set-Cookie` header
       */
      static serialize(name, value, attributes = {}) {
        return [
          `${this.encodeName(name)}=${this.encodeValue(value)}`,
          ...attributes.domain ? [`Domain=${attributes.domain}`] : [],
          ...attributes.path ? [`Path=${attributes.path}`] : [],
          ...attributes.expires ? [`Expires=${attributes.expires.toUTCString()}`] : [],
          ...attributes.maxAge ? [`Max-Age=${attributes.maxAge}`] : [],
          ...attributes.secure ? ["Secure"] : [],
          ...attributes.httpOnly ? ["HttpOnly"] : [],
          ...attributes.sameSite ? [`SameSite=${attributes.sameSite}`] : []
        ].join("; ");
      }
      /**
       * URI encodes all characters not compliant with RFC 6265 cookie-name syntax (namely, non-US-ASCII,
       * control characters and `()<>@,;:\"/[]?={} `) as well as `%` character to enable URI encoding support.
       * Refer to {@link https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1 RFC 6265 section 4.1.1.} for more details.
       */
      static encodeName = (str) => str.replace(/[^\x21\x23\x24\x26\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]+/g, encodeURIComponent).replace(/[()]/g, (s) => `%${s.charCodeAt(0).toString(16).toUpperCase()}`);
      /**
       * Safely URI decodes cookie name.
       */
      static decodeName = (str) => str.replace(/(%[\dA-Fa-f]{2})+/g, decodeURIComponent);
      /**
       * URI encodes all characters not compliant with RFC 6265 cookie-octet syntax (namely, non-US-ASCII,
       * control characters, whitespace, double quote, comma, semicolon and backslash) as well as `%` character
       * to enable URI encoding support.
       * Refer to {@link https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1 RFC 6265 section 4.1.1.} for more details.
       */
      static encodeValue = (str) => str.replace(/[^\x21\x23\x24\x26-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+/g, encodeURIComponent);
      /**
       * Safely URI decodes cookie value.
       */
      static decodeValue = (str) => str.replace(/(%[\dA-Fa-f]{2})+/g, decodeURIComponent);
    };
    exports.Cookies = Cookies;
    function getCookieDomain(cfDomain, disableCookieDomain, customCookieDomain = void 0) {
      if (disableCookieDomain) {
        return void 0;
      }
      if (customCookieDomain) {
        return customCookieDomain;
      }
      return cfDomain;
    }
    exports.getCookieDomain = getCookieDomain;
  }
});

// ../../node_modules/cognito-at-edge/dist/util/csrf.js
var require_csrf = __commonJS({
  "../../node_modules/cognito-at-edge/dist/util/csrf.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.generatePkceVerifier = exports.urlSafe = exports.signNonce = exports.sign = exports.generateSecret = exports.getCurrentTimestampInSeconds = exports.generateCSRFTokens = exports.generateNonce = exports.CSRF_CONFIG = exports.PKCE_COOKIE_NAME_SUFFIX = exports.NONCE_HMAC_COOKIE_NAME_SUFFIX = exports.NONCE_COOKIE_NAME_SUFFIX = void 0;
    var crypto_1 = require("crypto");
    exports.NONCE_COOKIE_NAME_SUFFIX = "nonce";
    exports.NONCE_HMAC_COOKIE_NAME_SUFFIX = "nonceHmac";
    exports.PKCE_COOKIE_NAME_SUFFIX = "pkce";
    exports.CSRF_CONFIG = {
      secretAllowedCharacters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
      pkceLength: 43,
      nonceLength: 16,
      nonceMaxAge: 60 * 60 * 24
    };
    function generateNonce() {
      const randomString = generateSecret(exports.CSRF_CONFIG.secretAllowedCharacters, exports.CSRF_CONFIG.nonceLength);
      return `${getCurrentTimestampInSeconds()}T${randomString}`;
    }
    exports.generateNonce = generateNonce;
    function generateCSRFTokens(redirectURI, signingSecret) {
      const nonce = generateNonce();
      const nonceHmac = signNonce(nonce, signingSecret);
      const state = exports.urlSafe.stringify(Buffer.from(JSON.stringify({
        nonce,
        redirect_uri: redirectURI
      })).toString("base64"));
      return {
        nonce,
        nonceHmac,
        state,
        ...generatePkceVerifier()
      };
    }
    exports.generateCSRFTokens = generateCSRFTokens;
    function getCurrentTimestampInSeconds() {
      return Date.now() / 1e3 || 0;
    }
    exports.getCurrentTimestampInSeconds = getCurrentTimestampInSeconds;
    function generateSecret(allowedCharacters, secretLength) {
      return [...new Array(secretLength)].map(() => allowedCharacters[(0, crypto_1.randomInt)(0, allowedCharacters.length)]).join("");
    }
    exports.generateSecret = generateSecret;
    function sign(stringToSign, secret, signatureLength) {
      const digest = (0, crypto_1.createHmac)("sha256", secret).update(stringToSign).digest("base64").slice(0, signatureLength);
      const signature = exports.urlSafe.stringify(digest);
      return signature;
    }
    exports.sign = sign;
    function signNonce(nonce, signingSecret) {
      return sign(nonce, signingSecret, exports.CSRF_CONFIG.nonceLength);
    }
    exports.signNonce = signNonce;
    exports.urlSafe = {
      /*
        Functions to translate base64-encoded strings, so they can be used:
        - in URL's without needing additional encoding
        - in OAuth2 PKCE verifier
        - in cookies (to be on the safe side, as = + / are in fact valid characters in cookies)
      
        stringify:
            use this on a base64-encoded string to translate = + / into replacement characters
      
        parse:
            use this on a string that was previously urlSafe.stringify'ed to return it to
            its prior pure-base64 form. Note that trailing = are not added, but NodeJS does not care
          */
      stringify: (b64encodedString) => b64encodedString.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"),
      parse: (b64encodedString) => b64encodedString.replace(/-/g, "+").replace(/_/g, "/")
    };
    function generatePkceVerifier() {
      const pkce = generateSecret(exports.CSRF_CONFIG.secretAllowedCharacters, exports.CSRF_CONFIG.pkceLength);
      const verifier = {
        pkce,
        pkceHash: exports.urlSafe.stringify((0, crypto_1.createHash)("sha256").update(pkce, "utf8").digest("base64"))
      };
      return verifier;
    }
    exports.generatePkceVerifier = generatePkceVerifier;
  }
});

// ../../node_modules/cognito-at-edge/dist/index.js
var require_dist = __commonJS({
  "../../node_modules/cognito-at-edge/dist/index.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.Authenticator = void 0;
    var aws_jwt_verify_1 = require_cjs();
    var axios_1 = require_axios2();
    var pino_1 = require_pino();
    var querystring_1 = require("querystring");
    var cookie_1 = require_cookie();
    var csrf_1 = require_csrf();
    var Authenticator2 = class {
      _region;
      _userPoolId;
      _userPoolAppId;
      _userPoolAppSecret;
      _userPoolDomain;
      _cookieExpirationDays;
      _disableCookieDomain;
      _httpOnly;
      _sameSite;
      _cookieBase;
      _cookiePath;
      _cookieDomain;
      _csrfProtection;
      _logoutConfiguration;
      _parseAuthPath;
      _cookieSettingsOverrides;
      _logger;
      _jwtVerifier;
      constructor(params) {
        this._verifyParams(params);
        this._region = params.region;
        this._userPoolId = params.userPoolId;
        this._userPoolAppId = params.userPoolAppId;
        this._userPoolAppSecret = params.userPoolAppSecret;
        this._userPoolDomain = params.userPoolDomain;
        this._cookieExpirationDays = params.cookieExpirationDays || 365;
        this._disableCookieDomain = "disableCookieDomain" in params && params.disableCookieDomain === true;
        this._cookieDomain = params.cookieDomain;
        this._httpOnly = "httpOnly" in params && params.httpOnly === true;
        this._sameSite = params.sameSite;
        this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
        this._cookiePath = params.cookiePath;
        this._cookieSettingsOverrides = params.cookieSettingsOverrides || {};
        this._logger = (0, pino_1.default)({
          level: params.logLevel || "silent",
          base: null
          //Remove pid, hostname and name logging as not usefull for Lambda
        });
        this._jwtVerifier = aws_jwt_verify_1.CognitoJwtVerifier.create({
          userPoolId: params.userPoolId,
          clientId: params.userPoolAppId,
          tokenUse: "id"
        });
        this._csrfProtection = params.csrfProtection;
        this._logoutConfiguration = params.logoutConfiguration;
        this._parseAuthPath = (params.parseAuthPath || "").replace(/^\//, "");
      }
      /**
       * Verify that constructor parameters are corrects.
       * @param  {object} params constructor params
       * @return {void} throw an exception if params are incorects.
       */
      _verifyParams(params) {
        if (typeof params !== "object") {
          throw new Error("Expected params to be an object");
        }
        ["region", "userPoolId", "userPoolAppId", "userPoolDomain"].forEach((param) => {
          if (typeof params[param] !== "string") {
            throw new Error(`Expected params.${param} to be a string`);
          }
        });
        if (params.cookieExpirationDays && typeof params.cookieExpirationDays !== "number") {
          throw new Error("Expected params.cookieExpirationDays to be a number");
        }
        if ("disableCookieDomain" in params && typeof params.disableCookieDomain !== "boolean") {
          throw new Error("Expected params.disableCookieDomain to be boolean");
        }
        if ("cookieDomain" in params && typeof params.cookieDomain !== "string") {
          throw new Error("Expected params.cookieDomain to be a string");
        }
        if ("httpOnly" in params && typeof params.httpOnly !== "boolean") {
          throw new Error("Expected params.httpOnly to be a boolean");
        }
        if (params.sameSite !== void 0 && !cookie_1.SAME_SITE_VALUES.includes(params.sameSite)) {
          throw new Error("Expected params.sameSite to be a Strict || Lax || None");
        }
        if ("cookiePath" in params && typeof params.cookiePath !== "string") {
          throw new Error("Expected params.cookiePath to be a string");
        }
        if (params.logoutConfiguration && !/\/\w+/.test(params.logoutConfiguration.logoutUri)) {
          throw new Error('Expected params.logoutConfiguration.logoutUri to be a valid non-empty string starting with "/"');
        }
      }
      /**
       * Exchange authorization code for tokens.
       * @param  {String} redirectURI Redirection URI.
       * @param  {String} code        Authorization code.
       * @return {Promise} Authenticated user tokens.
       */
      _fetchTokensFromCode(redirectURI, code) {
        const authorization = this._getAuthorization();
        const request = {
          url: `https://${this._userPoolDomain}/oauth2/token`,
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            ...authorization && { "Authorization": `Basic ${authorization}` }
          },
          data: (0, querystring_1.stringify)({
            client_id: this._userPoolAppId,
            code,
            grant_type: "authorization_code",
            redirect_uri: redirectURI
          })
        };
        this._logger.debug({ msg: "Fetching tokens from grant code...", request, code });
        return axios_1.default.request(request).then((resp) => {
          this._logger.debug({ msg: "Fetched tokens", tokens: resp.data });
          return {
            idToken: resp.data.id_token,
            accessToken: resp.data.access_token,
            refreshToken: resp.data.refresh_token
          };
        }).catch((err) => {
          this._logger.error({ msg: "Unable to fetch tokens from grant code", request, code });
          throw err;
        });
      }
      /**
       * Fetch accessTokens from refreshToken.
       * @param  {String} redirectURI Redirection URI.
       * @param  {String} refreshToken Refresh token.
       * @return {Promise<Tokens>} Refreshed user tokens.
       */
      _fetchTokensFromRefreshToken(redirectURI, refreshToken) {
        const authorization = this._getAuthorization();
        const request = {
          url: `https://${this._userPoolDomain}/oauth2/token`,
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            ...authorization && { "Authorization": `Basic ${authorization}` }
          },
          data: (0, querystring_1.stringify)({
            client_id: this._userPoolAppId,
            refresh_token: refreshToken,
            grant_type: "refresh_token",
            redirect_uri: redirectURI
          })
        };
        this._logger.debug({ msg: "Fetching tokens from refreshToken...", request, refreshToken });
        return axios_1.default.request(request).then((resp) => {
          this._logger.debug({ msg: "Fetched tokens", tokens: resp.data });
          return {
            idToken: resp.data.id_token,
            accessToken: resp.data.access_token
          };
        }).catch((err) => {
          this._logger.error({ msg: "Unable to fetch tokens from refreshToken", request, refreshToken });
          throw err;
        });
      }
      _getAuthorization() {
        return this._userPoolAppSecret && Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString("base64");
      }
      _validateCSRFCookies(request) {
        if (!this._csrfProtection) {
          throw new Error("_validateCSRFCookies should not be called if CSRF protection is disabled.");
        }
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const requestCookies = request.headers.cookie?.flatMap((h) => cookie_1.Cookies.parse(h.value)) || [];
        this._logger.debug({ msg: "Validating CSRF Cookies", requestCookies });
        const parsedState = JSON.parse(Buffer.from(csrf_1.urlSafe.parse(requestParams.state), "base64").toString());
        const { nonce: originalNonce, nonceHmac, pkce } = this._getCSRFTokensFromCookie(request.headers.cookie);
        if (!parsedState.nonce || !originalNonce || parsedState.nonce !== originalNonce) {
          if (!originalNonce) {
            throw new Error("Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).");
          }
          throw new Error("Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)");
        }
        if (!pkce) {
          throw new Error("Your browser didn't send the pkce cookie along, but it is required for security (prevent CSRF).");
        }
        const calculatedHmac = (0, csrf_1.signNonce)(parsedState.nonce, this._csrfProtection.nonceSigningSecret);
        if (calculatedHmac !== nonceHmac) {
          throw new Error(`Nonce signature mismatch! Expected ${calculatedHmac} but got ${nonceHmac}`);
        }
      }
      _getOverridenCookieAttributes(cookieAttributes = {}, cookieType) {
        const res = { ...cookieAttributes };
        const overrides = this._cookieSettingsOverrides?.[cookieType];
        if (overrides) {
          if (overrides.httpOnly !== void 0) {
            res.httpOnly = overrides.httpOnly;
          }
          if (overrides.sameSite !== void 0) {
            res.sameSite = overrides.sameSite;
          }
          if (overrides.path !== void 0) {
            res.path = overrides.path;
          }
          if (overrides.expirationDays !== void 0) {
            res.expires = new Date(Date.now() + overrides.expirationDays * 864e5);
          }
        }
        this._logger.debug({
          msg: "Cookie settings overriden",
          cookieAttributes,
          cookieType,
          cookieSettingsOverrides: this._cookieSettingsOverrides
        });
        return res;
      }
      /**
       * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
       * @param  {Object} tokens   Cognito User Pool tokens.
       * @param  {String} domain   Website domain.
       * @param  {String} location Path to redirection.
       * @return Lambda@Edge response.
       */
      async _getRedirectResponse(tokens, domain, location) {
        const decoded = await this._jwtVerifier.verify(tokens.idToken);
        const username = decoded["cognito:username"];
        const usernameBase = `${this._cookieBase}.${username}`;
        const cookieDomain = (0, cookie_1.getCookieDomain)(domain, this._disableCookieDomain, this._cookieDomain);
        const cookieAttributes = {
          domain: cookieDomain,
          expires: new Date(Date.now() + this._cookieExpirationDays * 864e5),
          secure: true,
          httpOnly: this._httpOnly,
          sameSite: this._sameSite,
          path: this._cookiePath
        };
        const cookies = [
          cookie_1.Cookies.serialize(`${usernameBase}.accessToken`, tokens.accessToken, this._getOverridenCookieAttributes(cookieAttributes, "accessToken")),
          cookie_1.Cookies.serialize(`${usernameBase}.idToken`, tokens.idToken, this._getOverridenCookieAttributes(cookieAttributes, "idToken")),
          ...tokens.refreshToken ? [cookie_1.Cookies.serialize(`${usernameBase}.refreshToken`, tokens.refreshToken, this._getOverridenCookieAttributes(cookieAttributes, "refreshToken"))] : [],
          cookie_1.Cookies.serialize(`${usernameBase}.tokenScopesString`, "phone email profile openid aws.cognito.signin.user.admin", cookieAttributes),
          cookie_1.Cookies.serialize(`${this._cookieBase}.LastAuthUser`, username, cookieAttributes)
        ];
        if (this._csrfProtection) {
          const csrfCookieAttributes = { ...cookieAttributes, domain: void 0, expires: /* @__PURE__ */ new Date() };
          cookies.push(cookie_1.Cookies.serialize(`${this._cookieBase}.${csrf_1.PKCE_COOKIE_NAME_SUFFIX}`, "", csrfCookieAttributes), cookie_1.Cookies.serialize(`${this._cookieBase}.${csrf_1.NONCE_COOKIE_NAME_SUFFIX}`, "", csrfCookieAttributes), cookie_1.Cookies.serialize(`${this._cookieBase}.${csrf_1.NONCE_HMAC_COOKIE_NAME_SUFFIX}`, "", csrfCookieAttributes));
        }
        const response = {
          status: "302",
          headers: {
            "location": [{
              key: "Location",
              value: location
            }],
            "cache-control": [{
              key: "Cache-Control",
              value: "no-cache, no-store, max-age=0, must-revalidate"
            }],
            "pragma": [{
              key: "Pragma",
              value: "no-cache"
            }],
            "set-cookie": cookies.map((c) => ({ key: "Set-Cookie", value: c }))
          }
        };
        this._logger.debug({ msg: "Generated set-cookie response", response });
        return response;
      }
      /**
       * Extract value of the authentication token from the request cookies.
       * @param  {Array}  cookieHeaders 'Cookie' request headers.
       * @return {Tokens} Extracted id token or access token. Null if not found.
       */
      _getTokensFromCookie(cookieHeaders) {
        if (!cookieHeaders) {
          this._logger.debug("Cookies weren't present in the request");
          throw new Error("Cookies weren't present in the request");
        }
        this._logger.debug({ msg: "Extracting authentication token from request cookie", cookieHeaders });
        const cookies = cookieHeaders.flatMap((h) => cookie_1.Cookies.parse(h.value));
        const tokenCookieNamePrefix = `${this._cookieBase}.`;
        const idTokenCookieNamePostfix = ".idToken";
        const refreshTokenCookieNamePostfix = ".refreshToken";
        const tokens = {};
        for (const { name, value } of cookies) {
          if (name.startsWith(tokenCookieNamePrefix) && name.endsWith(idTokenCookieNamePostfix)) {
            tokens.idToken = value;
          }
          if (name.startsWith(tokenCookieNamePrefix) && name.endsWith(refreshTokenCookieNamePostfix)) {
            tokens.refreshToken = value;
          }
        }
        if (!tokens.idToken && !tokens.refreshToken) {
          this._logger.debug("Neither idToken, nor refreshToken was present in request cookies");
          throw new Error("Neither idToken, nor refreshToken was present in request cookies");
        }
        this._logger.debug({ msg: "Found tokens in cookie", tokens });
        return tokens;
      }
      /**
       * Extract values of the CSRF tokens from the request cookies.
       * @param  {Array}  cookieHeaders 'Cookie' request headers.
       * @return {CSRFTokens} Extracted CSRF Tokens from cookie.
       */
      _getCSRFTokensFromCookie(cookieHeaders) {
        if (!cookieHeaders) {
          this._logger.debug("Cookies weren't present in the request");
          throw new Error("Cookies weren't present in the request");
        }
        this._logger.debug({ msg: "Extracting CSRF tokens from request cookie", cookieHeaders });
        const cookies = cookieHeaders.flatMap((h) => cookie_1.Cookies.parse(h.value));
        const csrfTokens = cookies.reduce((tokens, { name, value }) => {
          if (name.startsWith(this._cookieBase)) {
            [
              csrf_1.NONCE_COOKIE_NAME_SUFFIX,
              csrf_1.NONCE_HMAC_COOKIE_NAME_SUFFIX,
              csrf_1.PKCE_COOKIE_NAME_SUFFIX
            ].forEach((key) => {
              if (name.endsWith(`.${key}`)) {
                tokens[key] = value;
              }
            });
          }
          return tokens;
        }, {});
        this._logger.debug({ msg: "Found CSRF tokens in cookie", csrfTokens });
        return csrfTokens;
      }
      /**
       * Extracts the redirect uri from the state param. When CSRF protection is
       * enabled, redirect uri is encoded inside state along with other data. So, it
       * needs to be base64 decoded. When CSRF is not enabled, state can be used
       * directly.
       * @param {string} state
       * @returns {string}
       */
      _getRedirectUriFromState(state) {
        if (this._csrfProtection) {
          const parsedState = JSON.parse(Buffer.from(csrf_1.urlSafe.parse(state), "base64").toString());
          this._logger.debug({ msg: "Parsed state param to extract redirect uri", parsedState });
          return parsedState.redirect_uri;
        }
        return state;
      }
      async _revokeTokens(tokens) {
        const authorization = this._getAuthorization();
        const revokeRequest = {
          url: `https://${this._userPoolDomain}/oauth2/revoke`,
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            ...authorization && { "Authorization": `Basic ${authorization}` }
          },
          data: (0, querystring_1.stringify)({
            client_id: this._userPoolAppId,
            token: tokens.refreshToken
          })
        };
        this._logger.debug({ msg: "Revoking refreshToken...", request: revokeRequest, refreshToken: tokens.refreshToken });
        return axios_1.default.request(revokeRequest).then(() => {
          this._logger.debug({ msg: "Revoked refreshToken", refreshToken: tokens.refreshToken });
        }).catch((err) => {
          this._logger.error({ msg: "Unable to revoke refreshToken", request: revokeRequest, err: JSON.stringify(err) });
          throw err;
        });
      }
      async _clearCookies(event, tokens = {}) {
        this._logger.info({ msg: "Clearing cookies...", event, tokens });
        const { request } = event.Records[0].cf;
        const cfDomain = request.headers.host[0].value;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const redirectURI = this._logoutConfiguration?.logoutRedirectUri || requestParams.redirect_uri || `https://${cfDomain}`;
        const cookieDomain = (0, cookie_1.getCookieDomain)(cfDomain, this._disableCookieDomain, this._cookieDomain);
        const cookieAttributes = {
          domain: cookieDomain,
          expires: /* @__PURE__ */ new Date(),
          secure: true,
          httpOnly: this._httpOnly,
          sameSite: this._sameSite,
          path: this._cookiePath
        };
        let responseCookies = [];
        try {
          const decoded = await this._jwtVerifier.verify(tokens.idToken);
          const username = decoded["cognito:username"];
          this._logger.info({ msg: "Token verified. Clearing cookies...", idToken: tokens.idToken, username });
          const usernameBase = `${this._cookieBase}.${username}`;
          responseCookies = [
            cookie_1.Cookies.serialize(`${usernameBase}.accessToken`, "", cookieAttributes),
            cookie_1.Cookies.serialize(`${usernameBase}.idToken`, "", cookieAttributes),
            ...tokens.refreshToken ? [cookie_1.Cookies.serialize(`${usernameBase}.refreshToken`, "", cookieAttributes)] : [],
            cookie_1.Cookies.serialize(`${usernameBase}.tokenScopesString`, "", cookieAttributes),
            cookie_1.Cookies.serialize(`${this._cookieBase}.LastAuthUser`, "", cookieAttributes)
          ];
        } catch (err) {
          this._logger.info({
            msg: "Unable to verify token. Inferring data from request cookies and clearing them...",
            idToken: tokens.idToken
          });
          const requestCookies = request.headers.cookie?.flatMap((h) => cookie_1.Cookies.parse(h.value)) || [];
          for (const { name } of requestCookies) {
            if (name.startsWith(this._cookieBase)) {
              responseCookies.push(cookie_1.Cookies.serialize(name, "", cookieAttributes));
            }
          }
        }
        const response = {
          status: "302",
          headers: {
            "location": [{
              key: "Location",
              value: redirectURI
            }],
            "cache-control": [{
              key: "Cache-Control",
              value: "no-cache, no-store, max-age=0, must-revalidate"
            }],
            "pragma": [{
              key: "Pragma",
              value: "no-cache"
            }],
            "set-cookie": responseCookies.map((c) => ({ key: "Set-Cookie", value: c }))
          }
        };
        this._logger.debug({ msg: "Generated set-cookie response", response });
        return response;
      }
      /**
       * Get redirect to cognito userpool response
       * @param  {CloudFrontRequest}  request The original request
       * @param  {string}  redirectURI Redirection URI.
       * @return {CloudFrontResultResponse} Redirect response.
       */
      _getRedirectToCognitoUserPoolResponse(request, redirectURI) {
        const cfDomain = request.headers.host[0].value;
        let redirectPath = request.uri;
        if (request.querystring && request.querystring !== "") {
          redirectPath += encodeURIComponent("?" + request.querystring);
        }
        let oauthRedirectUri = redirectURI;
        if (this._parseAuthPath) {
          oauthRedirectUri = `https://${cfDomain}/${this._parseAuthPath}`;
        }
        let csrfTokens = {};
        let state = redirectPath;
        if (this._csrfProtection) {
          csrfTokens = (0, csrf_1.generateCSRFTokens)(redirectURI, this._csrfProtection.nonceSigningSecret);
          state = csrfTokens.state;
        }
        const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${oauthRedirectUri}&response_type=code&client_id=${this._userPoolAppId}&state=${state}`;
        this._logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`);
        let cookies;
        if (this._csrfProtection) {
          const cookieAttributes = {
            expires: new Date(Date.now() + 10 * 60 * 1e3),
            secure: true,
            httpOnly: this._httpOnly,
            sameSite: this._sameSite,
            path: this._cookiePath
          };
          cookies = [
            cookie_1.Cookies.serialize(`${this._cookieBase}.${csrf_1.PKCE_COOKIE_NAME_SUFFIX}`, csrfTokens.pkce || "", cookieAttributes),
            cookie_1.Cookies.serialize(`${this._cookieBase}.${csrf_1.NONCE_COOKIE_NAME_SUFFIX}`, csrfTokens.nonce || "", cookieAttributes),
            cookie_1.Cookies.serialize(`${this._cookieBase}.${csrf_1.NONCE_HMAC_COOKIE_NAME_SUFFIX}`, csrfTokens.nonceHmac || "", cookieAttributes)
          ];
        }
        const response = {
          status: "302",
          headers: {
            "location": [{
              key: "Location",
              value: userPoolUrl
            }],
            "cache-control": [{
              key: "Cache-Control",
              value: "no-cache, no-store, max-age=0, must-revalidate"
            }],
            "pragma": [{
              key: "Pragma",
              value: "no-cache"
            }],
            ...cookies ? { "set-cookie": cookies && cookies.map((c) => ({ key: "Set-Cookie", value: c })) } : {}
          }
        };
        return response;
      }
      /**
       * Handle Lambda@Edge event:
       *   * if authentication cookie is present and valid: forward the request
       *   * if authentication cookie is invalid, but refresh token is present: set cookies with refreshed tokens
       *   * if ?code=<grant code> is present: set cookies with new tokens
       *   * else redirect to the Cognito UserPool to authenticate the user
       * @param  {Object}  event Lambda@Edge event.
       * @return {Promise} CloudFront response.
       */
      async handle(event) {
        this._logger.debug({ msg: "Handling Lambda@Edge event", event });
        const { request } = event.Records[0].cf;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const cfDomain = request.headers.host[0].value;
        const redirectURI = `https://${cfDomain}`;
        try {
          const tokens = this._getTokensFromCookie(request.headers.cookie);
          if (this._logoutConfiguration && request.uri.startsWith(this._logoutConfiguration.logoutUri)) {
            this._logger.info({ msg: "Revoking tokens", tokens });
            await this._revokeTokens(tokens);
            this._logger.info({ msg: "Revoked tokens. Clearing cookies", tokens });
            return this._clearCookies(event, tokens);
          }
          try {
            this._logger.debug({ msg: "Verifying token...", tokens });
            const user = await this._jwtVerifier.verify(tokens.idToken);
            this._logger.info({ msg: "Forwarding request", path: request.uri, user });
            return request;
          } catch (err) {
            this._logger.info({ msg: "Token verification failed", tokens, refreshToken: tokens.refreshToken });
            if (tokens.refreshToken) {
              this._logger.debug({ msg: "Verifying idToken failed, verifying refresh token instead...", tokens, err });
              return await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken).then((tokens2) => this._getRedirectResponse(tokens2, cfDomain, request.uri));
            } else {
              throw err;
            }
          }
        } catch (err) {
          if (this._logoutConfiguration && request.uri.startsWith(this._logoutConfiguration.logoutUri)) {
            this._logger.info({ msg: "Clearing cookies", path: redirectURI });
            return this._clearCookies(event);
          }
          this._logger.debug("User isn't authenticated: %s", err);
          if (requestParams.code) {
            return this._fetchTokensFromCode(redirectURI, requestParams.code).then((tokens) => this._getRedirectResponse(tokens, cfDomain, this._getRedirectUriFromState(requestParams.state)));
          } else {
            return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
          }
        }
      }
      /**
       *
       * 1. If the token cookies are present in the request, send users to the redirect_uri
       * 2. If cookies are not present, initiate the authentication flow
       *
       * @param event Event that triggers this Lambda function
       * @returns Lambda response
       */
      async handleSignIn(event) {
        this._logger.debug({ msg: "Handling Lambda@Edge event", event });
        const { request } = event.Records[0].cf;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const cfDomain = request.headers.host[0].value;
        const redirectURI = requestParams.redirect_uri || `https://${cfDomain}`;
        try {
          const tokens = this._getTokensFromCookie(request.headers.cookie);
          this._logger.debug({ msg: "Verifying token...", tokens });
          const user = await this._jwtVerifier.verify(tokens.idToken);
          this._logger.info({ msg: "Redirecting user to", path: redirectURI, user });
          return {
            status: "302",
            headers: {
              "location": [{
                key: "Location",
                value: redirectURI
              }]
            }
          };
        } catch (err) {
          this._logger.debug("User isn't authenticated: %s", err);
          return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
        }
      }
      /**
       *
       * Handler that performs OAuth token exchange -- exchanges the authorization
       * code obtained from the query parameter from server for tokens -- and sets
       * tokens as cookies. This is done after performing CSRF checks, by verifying
       * that the information encoded in the state query parameter is related to the
       * one stored in the cookies.
       *
       * @param event Event that triggers this Lambda function
       * @returns Lambda response
       */
      async handleParseAuth(event) {
        this._logger.debug({ msg: "Handling Lambda@Edge event", event });
        const { request } = event.Records[0].cf;
        const cfDomain = request.headers.host[0].value;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        try {
          if (!this._parseAuthPath) {
            throw new Error("parseAuthPath is not set");
          }
          const redirectURI = `https://${cfDomain}/${this._parseAuthPath}`;
          if (requestParams.code) {
            if (this._csrfProtection) {
              this._validateCSRFCookies(request);
            }
            const tokens = await this._fetchTokensFromCode(redirectURI, requestParams.code);
            const location = this._getRedirectUriFromState(requestParams.state);
            return this._getRedirectResponse(tokens, cfDomain, location);
          } else {
            this._logger.debug({ msg: "Code param not found", requestParams });
            throw new Error("OAuth code parameter not found");
          }
        } catch (err) {
          this._logger.debug({ msg: "Unable to exchange code for tokens", err });
          return {
            status: "400",
            body: `${err}`
          };
        }
      }
      /**
       *
       * Uses the refreshToken present in the cookies to get a new set of tokens
       * from the authorization server. After fetching the tokens, they are sent
       * back to the client as cookies.
       *
       * @param event Event that triggers this Lambda function
       * @returns Lambda response
       */
      async handleRefreshToken(event) {
        this._logger.debug({ msg: "Handling Lambda@Edge event", event });
        const { request } = event.Records[0].cf;
        const cfDomain = request.headers.host[0].value;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const redirectURI = requestParams.redirect_uri || `https://${cfDomain}`;
        try {
          let tokens = this._getTokensFromCookie(request.headers.cookie);
          this._logger.debug({ msg: "Verifying token...", tokens });
          const user = await this._jwtVerifier.verify(tokens.idToken);
          this._logger.debug({ msg: "Refreshing tokens...", tokens, user });
          tokens = await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken);
          this._logger.debug({ msg: "Refreshed tokens...", tokens, user });
          return this._getRedirectResponse(tokens, cfDomain, redirectURI);
        } catch (err) {
          this._logger.debug("User isn't authenticated: %s", err);
          return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
        }
      }
      /**
       *
       * Revokes the refreshToken (which also invalidates the accessToken obtained
       * using that refreshToken) and clears the cookies. Even if the revoke
       * operation fails, clear cookies based on the cookie names present in the
       * request headers.
       *
       * @param event Event that triggers this Lambda function
       * @returns Lambda response
       */
      async handleSignOut(event) {
        this._logger.debug({ msg: "Handling Lambda@Edge event", event });
        const { request } = event.Records[0].cf;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const cfDomain = request.headers.host[0].value;
        const redirectURI = requestParams.redirect_uri || `https://${cfDomain}`;
        try {
          const tokens = this._getTokensFromCookie(request.headers.cookie);
          this._logger.info({ msg: "Revoking tokens", tokens });
          await this._revokeTokens(tokens);
          this._logger.info({ msg: "Revoked tokens. Clearing cookies...", tokens });
          return this._clearCookies(event, tokens);
        } catch (err) {
          this._logger.info({ msg: "Unable to revoke tokens. Clearing cookies...", path: redirectURI });
          return this._clearCookies(event);
        }
      }
    };
    exports.Authenticator = Authenticator2;
  }
});

// src/edge-lambda/index.ts
var edge_lambda_exports = {};
__export(edge_lambda_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(edge_lambda_exports);
var import_cognito_at_edge = __toESM(require_dist());
var import_client_ssm = require("@aws-sdk/client-ssm");
var ssmClient = new import_client_ssm.SSMClient({ region: "eu-central-1" });
async function getParameters() {
  const command = new import_client_ssm.GetParametersCommand({
    Names: [
      "BooksAppCognitoUserPoolId",
      "BooksAppCognitoUserPoolClientId",
      "BooksAppCognitoUserPoolDomain"
    ],
    WithDecryption: false
  });
  const response = await ssmClient.send(command);
  const userPoolId = response.Parameters?.find((param) => param.Name === "BooksAppCognitoUserPoolId")?.Value;
  const userPoolClientId = response.Parameters?.find((param) => param.Name === "BooksAppCognitoUserPoolClientId")?.Value;
  const userPoolDomain = response.Parameters?.find((param) => param.Name === "BooksAppCognitoUserPoolDomain")?.Value;
  return { userPoolId, userPoolClientId, userPoolDomain };
}
var authenticatorPromise = (async () => {
  const { userPoolId, userPoolClientId, userPoolDomain } = await getParameters();
  return new import_cognito_at_edge.Authenticator({
    region: "us-east-1",
    // user pool region
    userPoolId,
    // user pool ID
    userPoolAppId: userPoolClientId,
    // user pool app client ID
    userPoolDomain: `${userPoolDomain}.auth.eu-central-1.amazoncognito.com`
    // user pool domain
  });
})();
var handler = async (request) => {
  const authenticator = await authenticatorPromise;
  return authenticator.handle(request);
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
