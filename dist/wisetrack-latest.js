(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else if(typeof exports === 'object')
		exports["WiseTrack"] = factory();
	else
		root["WiseTrack"] = factory();
})(self, () => {
return /******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 3807:
/***/ ((__unused_webpack_module, __unused_webpack_exports, __webpack_require__) => {

var _Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: export type NavigatorT = Navigator & {
  msDoNotTrack?: any,
  userLanguage?: string
}*/
/*:: export type DocumentT = Document & {
  hidden: boolean,
  mozHidden?: boolean,
  msHidden?: boolean,
  oHidden?: boolean,
  webkitHidden?: boolean
}*/
/*:: export type AttributionMapT = $ReadOnly<{|
  adid: string,
  tracker_token: string,
  tracker_name: string,
  network?: string,
  campaign?: string,
  adgroup?: string,
  creative?: string,
  click_label?: string,
  state: string
|}>*/
/*:: export type AttributionWhiteListT = $ReadOnlyArray<$Keys<AttributionMapT>>*/
/*:: export type ActivityStateMapT = $Shape<{|
  uuid: string,
  lastActive: number,
  lastInterval: number,
  timeSpent: number,
  sessionWindow: number,
  sessionLength: number,
  sessionCount: number,
  eventCount: number,
  installed: boolean,
  attribution: AttributionMapT
|}>*/
/*:: export type CommonRequestParams = {|
  timeSpent: $PropertyType<ActivityStateMapT, 'timeSpent'>,
  sessionLength: $PropertyType<ActivityStateMapT, 'sessionLength'>,
  sessionCount: $PropertyType<ActivityStateMapT, 'sessionCount'>,
  lastInterval: $PropertyType<ActivityStateMapT, 'lastInterval'>,
  eventCount?: $PropertyType<ActivityStateMapT, 'eventCount'>
|}*/
/*:: export type GlobalKeyValueParamsT = {[key: string]: string}*/
/*:: export type EventRequestParamsT = {|
  eventToken: string,
  revenue?: string,
  currency?: string,
  callbackParams?: ?GlobalKeyValueParamsT,
  partnerParams?: ?GlobalKeyValueParamsT
|}*/
/*:: export type SessionRequestParamsT = {|
  callbackParams?: ?GlobalKeyValueParamsT,
  partnerParams?: ?GlobalKeyValueParamsT
|}*/
/*:: export type SdkClickRequestParamsT = {|
  installedAt: string,
  recentlyOpen: string,
  source: string,
  referrer: string
|}*/
/*:: export type WaitT = number*/
/*:: export type UrlT = '/session' | '/attribution' | '/event' | '/gdpr_forget_device' | '/sdk_click' | '/disable_third_party_sharing'*/
/*:: export type MethodT = 'GET' | 'POST' | 'PUT' | 'DELETE'*/
/*:: export type RequestParamsT = $Shape<{|
  createdAt?: string,
  initiatedBy?: 'web' ,
  ...SessionRequestParamsT,
  ...EventRequestParamsT,
  ...SdkClickRequestParamsT,
  ...CommonRequestParams
|}>*/
/*:: export type HttpRequestParamsT = $ReadOnly<{|
  endpoint: string,
  url: UrlT,
  method?: MethodT,
  params: $ReadOnly<{|
    attempts: number,
    ...RequestParamsT
  |}>
|}>*/
/*:: export type HttpSuccessResponseT = $ReadOnly<{|
  status: 'success',
  adid: string,
  timestamp: string,
  continue_in?: number,
  retry_in?: number,
  ask_in?: number,
  tracking_state?: number,
  attribution?: AttributionMapT,
  message?: string
|}>*/
/*:: export type ErrorCodeT =
  'TRANSACTION_ERROR' |
  'SERVER_MALFORMED_RESPONSE' |
  'SERVER_INTERNAL_ERROR' |
  'SERVER_CANNOT_PROCESS' |
  'NO_CONNECTION' |
  'SKIP' |
  'MISSING_URL'*/
/*:: export type HttpErrorResponseT = $ReadOnly<{|
  status: 'error',
  action: 'CONTINUE' | 'RETRY',
  response: {[string]: string} | string,
  message: string,
  code: ErrorCodeT
|}>*/
/*:: export type HttpFinishCbT = () => void*/
/*:: export type HttpRetryCbT = (number) => Promise<HttpSuccessResponseT | HttpErrorResponseT>*/
/*:: export type HttpContinueCbT = (HttpSuccessResponseT | HttpErrorResponseT, HttpFinishCbT, HttpRetryCbT) => mixed*/
/*:: export type AttributionStateT = {|
  state: 'same' | 'changed' | 'unknown'
|}*/
/*:: export type BackOffStrategyT = 'long' | 'short' | 'test'*/
/*:: export type GlobalParamsT = {|
  key: string,
  value: string
|}*/
/*:: export type GlobalParamsMapT = {
  callbackParams: Array<GlobalParamsT>,
  partnerParams: Array<GlobalParamsT>
}*/
/*:: export type EventParamsT = {|
  eventToken: string,
  revenue?: number,
  currency?: string,
  deduplicationId?: string,
  callbackParams?: Array<GlobalParamsT>,
  partnerParams?: Array<GlobalParamsT>
|}*/
/*:: export type BaseParamsT = $ReadOnly<$Shape<{
  appToken: string,
  environment: 'production' | 'sandbox',
  defaultTracker: string,
  externalDeviceId: string
}>>*/
/*:: export type CustomConfigT = $ReadOnly<$Shape<{
  customUrl: string,
  urlStrategy: 'india' | 'china',
  dataResidency: 'EU' | 'TR' | 'US',
  eventDeduplicationListLimit: number,
  namespace: string
}>>*/
/*:: export type LogOptionsT = $ReadOnly<$Shape<{|
  logLevel: 'none' | 'error' | 'warning' | 'info' | 'verbose',
  logOutput: string
|}>>*/
/*:: export type InitOptionsT = $ReadOnly<$Shape<{|
  appToken: $PropertyType<BaseParamsT, 'appToken'>,
  environment: $PropertyType<BaseParamsT, 'environment'>,
  defaultTracker: $PropertyType<BaseParamsT, 'defaultTracker'>,
  externalDeviceId: $PropertyType<BaseParamsT, 'externalDeviceId'>,
  customUrl: $PropertyType<CustomConfigT, 'customUrl'>,
  dataResidency: $PropertyType<CustomConfigT, 'dataResidency'>,
  urlStrategy: $PropertyType<CustomConfigT, 'urlStrategy'>,
  eventDeduplicationListLimit: $PropertyType<CustomConfigT, 'eventDeduplicationListLimit'>,
  namespace: $PropertyType<CustomConfigT, 'namespace'>,
  attributionCallback: (string, Object) => mixed
|}>>*/
/*:: export type BaseParamsListT = $ReadOnlyArray<$Keys<BaseParamsT>>*/
/*:: export type BaseParamsMandatoryListT = $ReadOnlyArray<'appToken' | 'environment'>*/
/*:: export type CustomConfigListT = $ReadOnlyArray<$Keys<CustomConfigT>>*/
/*:: export type CustomErrorT = {|
  name: string,
  message: string,
  interrupted?: boolean
|}*/
/*:: export type CreatedAtT = {|
  createdAt: string
|}*/
/*:: export type UpdatedAtT = {|
  updatedAt: string
|}*/
/*:: export type WebUuidT = {|
  androidUuid: string
|}*/
/*:: export type TrackEnabledT = {|
  trackingEnabled?: boolean
|}*/
/*:: export type PlatformT = {|
  initiatedBy: string,
  initiatedVersion: string
|}*/
/*:: export type NeedsResponseDetailsT = {|
  needsResponseDetails: String
|}*/
/*:: export type ReferrerParamsT = {|
  referrer: string
|}*/
/*:: export type LanguageT = {|
  language: string,
  country?: string
|}*/
/*:: export type MachineTypeT = {|
  machineType?: string
|}*/
/*:: export type QueueSizeT = {|
  queueSize: number
|}*/
/*:: export type PrimitiveConfigT = {|
  eventUrl?: string,
  sessionUrl ?: string,
  sdkClickUrl ?: string,
  sdkInfosUrl ?: string,
  AttributionUrl ?: string,
  packageInfoUrl ?: string,
  appSettingUrl ?: string,
  pageUrl ?: string,
  baseUrl ?: string,
  sdkSecure ?: boolean,
  sdkEnabled ?: boolean,
  sentryEnabled ?: boolean,
  forceUpdate ?: boolean,
  sdkUpdate ?: boolean,
  sessionInterval ?: string
|}*/
/*:: export type SmartBannerOptionsT = {|
  webToken: string,
  logLevel: 'none' | 'error' | 'warning' | 'info' | 'verbose',
  dataResidency: 'EU' | 'TR' | 'US',
|}*/
/*:: export type DeviceParamsT = {|
  osName?: string,
  osArch?: string,
  deviceType?: string,
  cpuType?: string,
  cpuLpc?: string,
  deviceName?: string,
  deviceManufacturer?: string,
  screenType?: string,
  browserVersion?: string,
  browserName?: string,
  browserPlatform?: string,
  sessionStorageEnabled?: string,
  sessionStorage?: string,
  indexedDbEnabled?: string,
  localStorageEnabled?: string,
  localStorage?: string,
  webGlSupport?: string,
  webGlFingerprint?: string,
  woutWidth?: string,
  woutHeight?: string,
  displayWidth?: string,
  displayHeight?: string,
  screenDensity?: string,
  displaySize?: string,
  screenSize?: string,
  webEngine?: string,
  uiMode?: string,
  uiStyle?: string,
  webUserAgent?: string,
  screenFormat?: string
|}*/
/*:: export type DefaultParamsT = {|
  ...CreatedAtT,
  ...SentAtT,
  ...WebUuidT,
  ...TrackEnabledT,
  ...PlatformT,
  ...NeedsResponseDetails,
  ...LanguageT,
  ...MachineTypeT,
  ...QueueSizeT
|}*/

/***/ }),

/***/ 452:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(8269), __webpack_require__(8214), __webpack_require__(888), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Lookup tables
	    var SBOX = [];
	    var INV_SBOX = [];
	    var SUB_MIX_0 = [];
	    var SUB_MIX_1 = [];
	    var SUB_MIX_2 = [];
	    var SUB_MIX_3 = [];
	    var INV_SUB_MIX_0 = [];
	    var INV_SUB_MIX_1 = [];
	    var INV_SUB_MIX_2 = [];
	    var INV_SUB_MIX_3 = [];

	    // Compute lookup tables
	    (function () {
	        // Compute double table
	        var d = [];
	        for (var i = 0; i < 256; i++) {
	            if (i < 128) {
	                d[i] = i << 1;
	            } else {
	                d[i] = (i << 1) ^ 0x11b;
	            }
	        }

	        // Walk GF(2^8)
	        var x = 0;
	        var xi = 0;
	        for (var i = 0; i < 256; i++) {
	            // Compute sbox
	            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
	            sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
	            SBOX[x] = sx;
	            INV_SBOX[sx] = x;

	            // Compute multiplication
	            var x2 = d[x];
	            var x4 = d[x2];
	            var x8 = d[x4];

	            // Compute sub bytes, mix columns tables
	            var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
	            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
	            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
	            SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
	            SUB_MIX_3[x] = t;

	            // Compute inv sub bytes, inv mix columns tables
	            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
	            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
	            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
	            INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
	            INV_SUB_MIX_3[sx] = t;

	            // Compute next counter
	            if (!x) {
	                x = xi = 1;
	            } else {
	                x = x2 ^ d[d[d[x8 ^ x2]]];
	                xi ^= d[d[xi]];
	            }
	        }
	    }());

	    // Precomputed Rcon lookup
	    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

	    /**
	     * AES block cipher algorithm.
	     */
	    var AES = C_algo.AES = BlockCipher.extend({
	        _doReset: function () {
	            var t;

	            // Skip reset of nRounds has been set before and key did not change
	            if (this._nRounds && this._keyPriorReset === this._key) {
	                return;
	            }

	            // Shortcuts
	            var key = this._keyPriorReset = this._key;
	            var keyWords = key.words;
	            var keySize = key.sigBytes / 4;

	            // Compute number of rounds
	            var nRounds = this._nRounds = keySize + 6;

	            // Compute number of key schedule rows
	            var ksRows = (nRounds + 1) * 4;

	            // Compute key schedule
	            var keySchedule = this._keySchedule = [];
	            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
	                if (ksRow < keySize) {
	                    keySchedule[ksRow] = keyWords[ksRow];
	                } else {
	                    t = keySchedule[ksRow - 1];

	                    if (!(ksRow % keySize)) {
	                        // Rot word
	                        t = (t << 8) | (t >>> 24);

	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

	                        // Mix Rcon
	                        t ^= RCON[(ksRow / keySize) | 0] << 24;
	                    } else if (keySize > 6 && ksRow % keySize == 4) {
	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
	                    }

	                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
	                }
	            }

	            // Compute inv key schedule
	            var invKeySchedule = this._invKeySchedule = [];
	            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
	                var ksRow = ksRows - invKsRow;

	                if (invKsRow % 4) {
	                    var t = keySchedule[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 4];
	                }

	                if (invKsRow < 4 || ksRow <= 4) {
	                    invKeySchedule[invKsRow] = t;
	                } else {
	                    invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
	                                               INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
	                }
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
	        },

	        decryptBlock: function (M, offset) {
	            // Swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;

	            this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

	            // Inv swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;
	        },

	        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
	            // Shortcut
	            var nRounds = this._nRounds;

	            // Get input, add round key
	            var s0 = M[offset]     ^ keySchedule[0];
	            var s1 = M[offset + 1] ^ keySchedule[1];
	            var s2 = M[offset + 2] ^ keySchedule[2];
	            var s3 = M[offset + 3] ^ keySchedule[3];

	            // Key schedule row counter
	            var ksRow = 4;

	            // Rounds
	            for (var round = 1; round < nRounds; round++) {
	                // Shift rows, sub bytes, mix columns, add round key
	                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
	                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
	                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
	                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

	                // Update state
	                s0 = t0;
	                s1 = t1;
	                s2 = t2;
	                s3 = t3;
	            }

	            // Shift rows, sub bytes, add round key
	            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
	            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
	            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
	            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

	            // Set output
	            M[offset]     = t0;
	            M[offset + 1] = t1;
	            M[offset + 2] = t2;
	            M[offset + 3] = t3;
	        },

	        keySize: 256/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
	     */
	    C.AES = BlockCipher._createHelper(AES);
	}());


	return CryptoJS.AES;

}));

/***/ }),

/***/ 7407:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(8269), __webpack_require__(8214), __webpack_require__(888), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    const N = 16;

	    //Origin pbox and sbox, derived from PI
	    const ORIG_P = [
	        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
	        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
	        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
	        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
	        0x9216D5D9, 0x8979FB1B
	    ];

	    const ORIG_S = [
	        [   0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7,
	            0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
	            0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
	            0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E,
	            0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE,
	            0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013,
	            0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF,
	            0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E,
	            0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
	            0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440,
	            0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE,
	            0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A,
	            0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E,
	            0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677,
	            0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193,
	            0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032,
	            0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88,
	            0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
	            0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E,
	            0x21C66842, 0xF6E96C9A, 0x670C9C61, 0xABD388F0,
	            0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3,
	            0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98,
	            0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88,
	            0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE,
	            0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6,
	            0x4ED3AA62, 0x363F7706, 0x1BFEDF72, 0x429B023D,
	            0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B,
	            0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7,
	            0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA,
	            0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463,
	            0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F,
	            0x6DFC511F, 0x9B30952C, 0xCC814544, 0xAF5EBD09,
	            0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3,
	            0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB,
	            0x5579C0BD, 0x1A60320A, 0xD6A100C6, 0x402C7279,
	            0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8,
	            0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB,
	            0x323DB5FA, 0xFD238760, 0x53317B48, 0x3E00DF82,
	            0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB,
	            0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573,
	            0x695B27B0, 0xBBCA58C8, 0xE1FFA35D, 0xB8F011A0,
	            0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B,
	            0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790,
	            0xE1DDF2DA, 0xA4CB7E33, 0x62FB1341, 0xCEE4C6E8,
	            0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4,
	            0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0,
	            0xD08ED1D0, 0xAFC725E0, 0x8E3C5B2F, 0x8E7594B7,
	            0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C,
	            0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD,
	            0x2F2F2218, 0xBE0E1777, 0xEA752DFE, 0x8B021FA1,
	            0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299,
	            0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9,
	            0x165FA266, 0x80957705, 0x93CC7314, 0x211A1477,
	            0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF,
	            0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49,
	            0x00250E2D, 0x2071B35E, 0x226800BB, 0x57B8E0AF,
	            0x2464369B, 0xF009B91E, 0x5563911D, 0x59DFA6AA,
	            0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5,
	            0x83260376, 0x6295CFA9, 0x11C81968, 0x4E734A41,
	            0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915,
	            0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400,
	            0x08BA6FB5, 0x571BE91F, 0xF296EC6B, 0x2A0DD915,
	            0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664,
	            0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A   ],
	        [   0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623,
	            0xAD6EA6B0, 0x49A7DF7D, 0x9CEE60B8, 0x8FEDB266,
	            0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1,
	            0x193602A5, 0x75094C29, 0xA0591340, 0xE4183A3E,
	            0x3F54989A, 0x5B429D65, 0x6B8FE4D6, 0x99F73FD6,
	            0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1,
	            0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E,
	            0x09686B3F, 0x3EBAEFC9, 0x3C971814, 0x6B6A70A1,
	            0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737,
	            0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8,
	            0xB03ADA37, 0xF0500C0D, 0xF01C1F04, 0x0200B3FF,
	            0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD,
	            0xD19113F9, 0x7CA92FF6, 0x94324773, 0x22F54701,
	            0x3AE5E581, 0x37C2DADC, 0xC8B57634, 0x9AF3DDA7,
	            0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41,
	            0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331,
	            0x4E548B38, 0x4F6DB908, 0x6F420D03, 0xF60A04BF,
	            0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF,
	            0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E,
	            0x5512721F, 0x2E6B7124, 0x501ADDE6, 0x9F84CD87,
	            0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C,
	            0xEC7AEC3A, 0xDB851DFA, 0x63094366, 0xC464C3D2,
	            0xEF1C1847, 0x3215D908, 0xDD433B37, 0x24C2BA16,
	            0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD,
	            0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B,
	            0x043556F1, 0xD7A3C76B, 0x3C11183B, 0x5924A509,
	            0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E,
	            0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3,
	            0x771FE71C, 0x4E3D06FA, 0x2965DCB9, 0x99E71D0F,
	            0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A,
	            0xC6150EBA, 0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4,
	            0xF2F74EA7, 0x361D2B3D, 0x1939260F, 0x19C27960,
	            0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66,
	            0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28,
	            0xC332DDEF, 0xBE6C5AA5, 0x65582185, 0x68AB9802,
	            0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84,
	            0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510,
	            0x13CCA830, 0xEB61BD96, 0x0334FE1E, 0xAA0363CF,
	            0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14,
	            0xEECC86BC, 0x60622CA7, 0x9CAB5CAB, 0xB2F3846E,
	            0x648B1EAF, 0x19BDF0CA, 0xA02369B9, 0x655ABB50,
	            0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7,
	            0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8,
	            0xF837889A, 0x97E32D77, 0x11ED935F, 0x16681281,
	            0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99,
	            0x57F584A5, 0x1B227263, 0x9B83C3FF, 0x1AC24696,
	            0xCDB30AEB, 0x532E3054, 0x8FD948E4, 0x6DBC3128,
	            0x58EBF2EF, 0x34C6FFEA, 0xFE28ED61, 0xEE7C3C73,
	            0x5D4A14D9, 0xE864B7E3, 0x42105D14, 0x203E13E0,
	            0x45EEE2B6, 0xA3AAABEA, 0xDB6C4F15, 0xFACB4FD0,
	            0xC742F442, 0xEF6ABBB5, 0x654F3B1D, 0x41CD2105,
	            0xD81E799E, 0x86854DC7, 0xE44B476A, 0x3D816250,
	            0xCF62A1F2, 0x5B8D2646, 0xFC8883A0, 0xC1C7B6A3,
	            0x7F1524C3, 0x69CB7492, 0x47848A0B, 0x5692B285,
	            0x095BBF00, 0xAD19489D, 0x1462B174, 0x23820E00,
	            0x58428D2A, 0x0C55F5EA, 0x1DADF43E, 0x233F7061,
	            0x3372F092, 0x8D937E41, 0xD65FECF1, 0x6C223BDB,
	            0x7CDE3759, 0xCBEE7460, 0x4085F2A7, 0xCE77326E,
	            0xA6078084, 0x19F8509E, 0xE8EFD855, 0x61D99735,
	            0xA969A7AA, 0xC50C06C2, 0x5A04ABFC, 0x800BCADC,
	            0x9E447A2E, 0xC3453484, 0xFDD56705, 0x0E1E9EC9,
	            0xDB73DBD3, 0x105588CD, 0x675FDA79, 0xE3674340,
	            0xC5C43465, 0x713E38D8, 0x3D28F89E, 0xF16DFF20,
	            0x153E21E7, 0x8FB03D4A, 0xE6E39F2B, 0xDB83ADF7   ],
	        [   0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934,
	            0x411520F7, 0x7602D4F7, 0xBCF46B2E, 0xD4A20068,
	            0xD4082471, 0x3320F46A, 0x43B7D4B7, 0x500061AF,
	            0x1E39F62E, 0x97244546, 0x14214F74, 0xBF8B8840,
	            0x4D95FC1D, 0x96B591AF, 0x70F4DDD3, 0x66A02F45,
	            0xBFBC09EC, 0x03BD9785, 0x7FAC6DD0, 0x31CB8504,
	            0x96EB27B3, 0x55FD3941, 0xDA2547E6, 0xABCA0A9A,
	            0x28507825, 0x530429F4, 0x0A2C86DA, 0xE9B66DFB,
	            0x68DC1462, 0xD7486900, 0x680EC0A4, 0x27A18DEE,
	            0x4F3FFEA2, 0xE887AD8C, 0xB58CE006, 0x7AF4D6B6,
	            0xAACE1E7C, 0xD3375FEC, 0xCE78A399, 0x406B2A42,
	            0x20FE9E35, 0xD9F385B9, 0xEE39D7AB, 0x3B124E8B,
	            0x1DC9FAF7, 0x4B6D1856, 0x26A36631, 0xEAE397B2,
	            0x3A6EFA74, 0xDD5B4332, 0x6841E7F7, 0xCA7820FB,
	            0xFB0AF54E, 0xD8FEB397, 0x454056AC, 0xBA489527,
	            0x55533A3A, 0x20838D87, 0xFE6BA9B7, 0xD096954B,
	            0x55A867BC, 0xA1159A58, 0xCCA92963, 0x99E1DB33,
	            0xA62A4A56, 0x3F3125F9, 0x5EF47E1C, 0x9029317C,
	            0xFDF8E802, 0x04272F70, 0x80BB155C, 0x05282CE3,
	            0x95C11548, 0xE4C66D22, 0x48C1133F, 0xC70F86DC,
	            0x07F9C9EE, 0x41041F0F, 0x404779A4, 0x5D886E17,
	            0x325F51EB, 0xD59BC0D1, 0xF2BCC18F, 0x41113564,
	            0x257B7834, 0x602A9C60, 0xDFF8E8A3, 0x1F636C1B,
	            0x0E12B4C2, 0x02E1329E, 0xAF664FD1, 0xCAD18115,
	            0x6B2395E0, 0x333E92E1, 0x3B240B62, 0xEEBEB922,
	            0x85B2A20E, 0xE6BA0D99, 0xDE720C8C, 0x2DA2F728,
	            0xD0127845, 0x95B794FD, 0x647D0862, 0xE7CCF5F0,
	            0x5449A36F, 0x877D48FA, 0xC39DFD27, 0xF33E8D1E,
	            0x0A476341, 0x992EFF74, 0x3A6F6EAB, 0xF4F8FD37,
	            0xA812DC60, 0xA1EBDDF8, 0x991BE14C, 0xDB6E6B0D,
	            0xC67B5510, 0x6D672C37, 0x2765D43B, 0xDCD0E804,
	            0xF1290DC7, 0xCC00FFA3, 0xB5390F92, 0x690FED0B,
	            0x667B9FFB, 0xCEDB7D9C, 0xA091CF0B, 0xD9155EA3,
	            0xBB132F88, 0x515BAD24, 0x7B9479BF, 0x763BD6EB,
	            0x37392EB3, 0xCC115979, 0x8026E297, 0xF42E312D,
	            0x6842ADA7, 0xC66A2B3B, 0x12754CCC, 0x782EF11C,
	            0x6A124237, 0xB79251E7, 0x06A1BBE6, 0x4BFB6350,
	            0x1A6B1018, 0x11CAEDFA, 0x3D25BDD8, 0xE2E1C3C9,
	            0x44421659, 0x0A121386, 0xD90CEC6E, 0xD5ABEA2A,
	            0x64AF674E, 0xDA86A85F, 0xBEBFE988, 0x64E4C3FE,
	            0x9DBC8057, 0xF0F7C086, 0x60787BF8, 0x6003604D,
	            0xD1FD8346, 0xF6381FB0, 0x7745AE04, 0xD736FCCC,
	            0x83426B33, 0xF01EAB71, 0xB0804187, 0x3C005E5F,
	            0x77A057BE, 0xBDE8AE24, 0x55464299, 0xBF582E61,
	            0x4E58F48F, 0xF2DDFDA2, 0xF474EF38, 0x8789BDC2,
	            0x5366F9C3, 0xC8B38E74, 0xB475F255, 0x46FCD9B9,
	            0x7AEB2661, 0x8B1DDF84, 0x846A0E79, 0x915F95E2,
	            0x466E598E, 0x20B45770, 0x8CD55591, 0xC902DE4C,
	            0xB90BACE1, 0xBB8205D0, 0x11A86248, 0x7574A99E,
	            0xB77F19B6, 0xE0A9DC09, 0x662D09A1, 0xC4324633,
	            0xE85A1F02, 0x09F0BE8C, 0x4A99A025, 0x1D6EFE10,
	            0x1AB93D1D, 0x0BA5A4DF, 0xA186F20F, 0x2868F169,
	            0xDCB7DA83, 0x573906FE, 0xA1E2CE9B, 0x4FCD7F52,
	            0x50115E01, 0xA70683FA, 0xA002B5C4, 0x0DE6D027,
	            0x9AF88C27, 0x773F8641, 0xC3604C06, 0x61A806B5,
	            0xF0177A28, 0xC0F586E0, 0x006058AA, 0x30DC7D62,
	            0x11E69ED7, 0x2338EA63, 0x53C2DD94, 0xC2C21634,
	            0xBBCBEE56, 0x90BCB6DE, 0xEBFC7DA1, 0xCE591D76,
	            0x6F05E409, 0x4B7C0188, 0x39720A3D, 0x7C927C24,
	            0x86E3725F, 0x724D9DB9, 0x1AC15BB4, 0xD39EB8FC,
	            0xED545578, 0x08FCA5B5, 0xD83D7CD3, 0x4DAD0FC4,
	            0x1E50EF5E, 0xB161E6F8, 0xA28514D9, 0x6C51133C,
	            0x6FD5C7E7, 0x56E14EC4, 0x362ABFCE, 0xDDC6C837,
	            0xD79A3234, 0x92638212, 0x670EFA8E, 0x406000E0  ],
	        [   0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B,
	            0x5CB0679E, 0x4FA33742, 0xD3822740, 0x99BC9BBE,
	            0xD5118E9D, 0xBF0F7315, 0xD62D1C7E, 0xC700C47B,
	            0xB78C1B6B, 0x21A19045, 0xB26EB1BE, 0x6A366EB4,
	            0x5748AB2F, 0xBC946E79, 0xC6A376D2, 0x6549C2C8,
	            0x530FF8EE, 0x468DDE7D, 0xD5730A1D, 0x4CD04DC6,
	            0x2939BBDB, 0xA9BA4650, 0xAC9526E8, 0xBE5EE304,
	            0xA1FAD5F0, 0x6A2D519A, 0x63EF8CE2, 0x9A86EE22,
	            0xC089C2B8, 0x43242EF6, 0xA51E03AA, 0x9CF2D0A4,
	            0x83C061BA, 0x9BE96A4D, 0x8FE51550, 0xBA645BD6,
	            0x2826A2F9, 0xA73A3AE1, 0x4BA99586, 0xEF5562E9,
	            0xC72FEFD3, 0xF752F7DA, 0x3F046F69, 0x77FA0A59,
	            0x80E4A915, 0x87B08601, 0x9B09E6AD, 0x3B3EE593,
	            0xE990FD5A, 0x9E34D797, 0x2CF0B7D9, 0x022B8B51,
	            0x96D5AC3A, 0x017DA67D, 0xD1CF3ED6, 0x7C7D2D28,
	            0x1F9F25CF, 0xADF2B89B, 0x5AD6B472, 0x5A88F54C,
	            0xE029AC71, 0xE019A5E6, 0x47B0ACFD, 0xED93FA9B,
	            0xE8D3C48D, 0x283B57CC, 0xF8D56629, 0x79132E28,
	            0x785F0191, 0xED756055, 0xF7960E44, 0xE3D35E8C,
	            0x15056DD4, 0x88F46DBA, 0x03A16125, 0x0564F0BD,
	            0xC3EB9E15, 0x3C9057A2, 0x97271AEC, 0xA93A072A,
	            0x1B3F6D9B, 0x1E6321F5, 0xF59C66FB, 0x26DCF319,
	            0x7533D928, 0xB155FDF5, 0x03563482, 0x8ABA3CBB,
	            0x28517711, 0xC20AD9F8, 0xABCC5167, 0xCCAD925F,
	            0x4DE81751, 0x3830DC8E, 0x379D5862, 0x9320F991,
	            0xEA7A90C2, 0xFB3E7BCE, 0x5121CE64, 0x774FBE32,
	            0xA8B6E37E, 0xC3293D46, 0x48DE5369, 0x6413E680,
	            0xA2AE0810, 0xDD6DB224, 0x69852DFD, 0x09072166,
	            0xB39A460A, 0x6445C0DD, 0x586CDECF, 0x1C20C8AE,
	            0x5BBEF7DD, 0x1B588D40, 0xCCD2017F, 0x6BB4E3BB,
	            0xDDA26A7E, 0x3A59FF45, 0x3E350A44, 0xBCB4CDD5,
	            0x72EACEA8, 0xFA6484BB, 0x8D6612AE, 0xBF3C6F47,
	            0xD29BE463, 0x542F5D9E, 0xAEC2771B, 0xF64E6370,
	            0x740E0D8D, 0xE75B1357, 0xF8721671, 0xAF537D5D,
	            0x4040CB08, 0x4EB4E2CC, 0x34D2466A, 0x0115AF84,
	            0xE1B00428, 0x95983A1D, 0x06B89FB4, 0xCE6EA048,
	            0x6F3F3B82, 0x3520AB82, 0x011A1D4B, 0x277227F8,
	            0x611560B1, 0xE7933FDC, 0xBB3A792B, 0x344525BD,
	            0xA08839E1, 0x51CE794B, 0x2F32C9B7, 0xA01FBAC9,
	            0xE01CC87E, 0xBCC7D1F6, 0xCF0111C3, 0xA1E8AAC7,
	            0x1A908749, 0xD44FBD9A, 0xD0DADECB, 0xD50ADA38,
	            0x0339C32A, 0xC6913667, 0x8DF9317C, 0xE0B12B4F,
	            0xF79E59B7, 0x43F5BB3A, 0xF2D519FF, 0x27D9459C,
	            0xBF97222C, 0x15E6FC2A, 0x0F91FC71, 0x9B941525,
	            0xFAE59361, 0xCEB69CEB, 0xC2A86459, 0x12BAA8D1,
	            0xB6C1075E, 0xE3056A0C, 0x10D25065, 0xCB03A442,
	            0xE0EC6E0E, 0x1698DB3B, 0x4C98A0BE, 0x3278E964,
	            0x9F1F9532, 0xE0D392DF, 0xD3A0342B, 0x8971F21E,
	            0x1B0A7441, 0x4BA3348C, 0xC5BE7120, 0xC37632D8,
	            0xDF359F8D, 0x9B992F2E, 0xE60B6F47, 0x0FE3F11D,
	            0xE54CDA54, 0x1EDAD891, 0xCE6279CF, 0xCD3E7E6F,
	            0x1618B166, 0xFD2C1D05, 0x848FD2C5, 0xF6FB2299,
	            0xF523F357, 0xA6327623, 0x93A83531, 0x56CCCD02,
	            0xACF08162, 0x5A75EBB5, 0x6E163697, 0x88D273CC,
	            0xDE966292, 0x81B949D0, 0x4C50901B, 0x71C65614,
	            0xE6C6C7BD, 0x327A140A, 0x45E1D006, 0xC3F27B9A,
	            0xC9AA53FD, 0x62A80F00, 0xBB25BFE2, 0x35BDD2F6,
	            0x71126905, 0xB2040222, 0xB6CBCF7C, 0xCD769C2B,
	            0x53113EC0, 0x1640E3D3, 0x38ABBD60, 0x2547ADF0,
	            0xBA38209C, 0xF746CE76, 0x77AFA1C5, 0x20756060,
	            0x85CBFE4E, 0x8AE88DD8, 0x7AAAF9B0, 0x4CF9AA7E,
	            0x1948C25C, 0x02FB8A8C, 0x01C36AE4, 0xD6EBE1F9,
	            0x90D4F869, 0xA65CDEA0, 0x3F09252D, 0xC208E69F,
	            0xB74E6132, 0xCE77E25B, 0x578FDFE3, 0x3AC372E6  ]
	    ];

	    var BLOWFISH_CTX = {
	        pbox: [],
	        sbox: []
	    }

	    function F(ctx, x){
	        let a = (x >> 24) & 0xFF;
	        let b = (x >> 16) & 0xFF;
	        let c = (x >> 8) & 0xFF;
	        let d = x & 0xFF;

	        let y = ctx.sbox[0][a] + ctx.sbox[1][b];
	        y = y ^ ctx.sbox[2][c];
	        y = y + ctx.sbox[3][d];

	        return y;
	    }

	    function BlowFish_Encrypt(ctx, left, right){
	        let Xl = left;
	        let Xr = right;
	        let temp;

	        for(let i = 0; i < N; ++i){
	            Xl = Xl ^ ctx.pbox[i];
	            Xr = F(ctx, Xl) ^ Xr;

	            temp = Xl;
	            Xl = Xr;
	            Xr = temp;
	        }

	        temp = Xl;
	        Xl = Xr;
	        Xr = temp;

	        Xr = Xr ^ ctx.pbox[N];
	        Xl = Xl ^ ctx.pbox[N + 1];

	        return {left: Xl, right: Xr};
	    }

	    function BlowFish_Decrypt(ctx, left, right){
	        let Xl = left;
	        let Xr = right;
	        let temp;

	        for(let i = N + 1; i > 1; --i){
	            Xl = Xl ^ ctx.pbox[i];
	            Xr = F(ctx, Xl) ^ Xr;

	            temp = Xl;
	            Xl = Xr;
	            Xr = temp;
	        }

	        temp = Xl;
	        Xl = Xr;
	        Xr = temp;

	        Xr = Xr ^ ctx.pbox[1];
	        Xl = Xl ^ ctx.pbox[0];

	        return {left: Xl, right: Xr};
	    }

	    /**
	     * Initialization ctx's pbox and sbox.
	     *
	     * @param {Object} ctx The object has pbox and sbox.
	     * @param {Array} key An array of 32-bit words.
	     * @param {int} keysize The length of the key.
	     *
	     * @example
	     *
	     *     BlowFishInit(BLOWFISH_CTX, key, 128/32);
	     */
	    function BlowFishInit(ctx, key, keysize)
	    {
	        for(let Row = 0; Row < 4; Row++)
	        {
	            ctx.sbox[Row] = [];
	            for(let Col = 0; Col < 256; Col++)
	            {
	                ctx.sbox[Row][Col] = ORIG_S[Row][Col];
	            }
	        }

	        let keyIndex = 0;
	        for(let index = 0; index < N + 2; index++)
	        {
	            ctx.pbox[index] = ORIG_P[index] ^ key[keyIndex];
	            keyIndex++;
	            if(keyIndex >= keysize)
	            {
	                keyIndex = 0;
	            }
	        }

	        let Data1 = 0;
	        let Data2 = 0;
	        let res = 0;
	        for(let i = 0; i < N + 2; i += 2)
	        {
	            res = BlowFish_Encrypt(ctx, Data1, Data2);
	            Data1 = res.left;
	            Data2 = res.right;
	            ctx.pbox[i] = Data1;
	            ctx.pbox[i + 1] = Data2;
	        }

	        for(let i = 0; i < 4; i++)
	        {
	            for(let j = 0; j < 256; j += 2)
	            {
	                res = BlowFish_Encrypt(ctx, Data1, Data2);
	                Data1 = res.left;
	                Data2 = res.right;
	                ctx.sbox[i][j] = Data1;
	                ctx.sbox[i][j + 1] = Data2;
	            }
	        }

	        return true;
	    }

	    /**
	     * Blowfish block cipher algorithm.
	     */
	    var Blowfish = C_algo.Blowfish = BlockCipher.extend({
	        _doReset: function () {
	            // Skip reset of nRounds has been set before and key did not change
	            if (this._keyPriorReset === this._key) {
	                return;
	            }

	            // Shortcuts
	            var key = this._keyPriorReset = this._key;
	            var keyWords = key.words;
	            var keySize = key.sigBytes / 4;

	            //Initialization pbox and sbox
	            BlowFishInit(BLOWFISH_CTX, keyWords, keySize);
	        },

	        encryptBlock: function (M, offset) {
	            var res = BlowFish_Encrypt(BLOWFISH_CTX, M[offset], M[offset + 1]);
	            M[offset] = res.left;
	            M[offset + 1] = res.right;
	        },

	        decryptBlock: function (M, offset) {
	            var res = BlowFish_Decrypt(BLOWFISH_CTX, M[offset], M[offset + 1]);
	            M[offset] = res.left;
	            M[offset + 1] = res.right;
	        },

	        blockSize: 64/32,

	        keySize: 128/32,

	        ivSize: 64/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.Blowfish.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.Blowfish.decrypt(ciphertext, key, cfg);
	     */
	    C.Blowfish = BlockCipher._createHelper(Blowfish);
	}());


	return CryptoJS.Blowfish;

}));

/***/ }),

/***/ 5109:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(888));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Cipher core components.
	 */
	CryptoJS.lib.Cipher || (function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var Base64 = C_enc.Base64;
	    var C_algo = C.algo;
	    var EvpKDF = C_algo.EvpKDF;

	    /**
	     * Abstract base cipher template.
	     *
	     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
	     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
	     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
	     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
	     */
	    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {WordArray} iv The IV to use for this operation.
	         */
	        cfg: Base.extend(),

	        /**
	         * Creates this cipher in encryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createEncryptor: function (key, cfg) {
	            return this.create(this._ENC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Creates this cipher in decryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createDecryptor: function (key, cfg) {
	            return this.create(this._DEC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Initializes a newly created cipher.
	         *
	         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
	         */
	        init: function (xformMode, key, cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Store transform mode and key
	            this._xformMode = xformMode;
	            this._key = key;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this cipher to its initial state.
	         *
	         * @example
	         *
	         *     cipher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-cipher logic
	            this._doReset();
	        },

	        /**
	         * Adds data to be encrypted or decrypted.
	         *
	         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.process('data');
	         *     var encrypted = cipher.process(wordArray);
	         */
	        process: function (dataUpdate) {
	            // Append
	            this._append(dataUpdate);

	            // Process available blocks
	            return this._process();
	        },

	        /**
	         * Finalizes the encryption or decryption process.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after final processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.finalize();
	         *     var encrypted = cipher.finalize('data');
	         *     var encrypted = cipher.finalize(wordArray);
	         */
	        finalize: function (dataUpdate) {
	            // Final data update
	            if (dataUpdate) {
	                this._append(dataUpdate);
	            }

	            // Perform concrete-cipher logic
	            var finalProcessedData = this._doFinalize();

	            return finalProcessedData;
	        },

	        keySize: 128/32,

	        ivSize: 128/32,

	        _ENC_XFORM_MODE: 1,

	        _DEC_XFORM_MODE: 2,

	        /**
	         * Creates shortcut functions to a cipher's object interface.
	         *
	         * @param {Cipher} cipher The cipher to create a helper for.
	         *
	         * @return {Object} An object with encrypt and decrypt shortcut functions.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
	         */
	        _createHelper: (function () {
	            function selectCipherStrategy(key) {
	                if (typeof key == 'string') {
	                    return PasswordBasedCipher;
	                } else {
	                    return SerializableCipher;
	                }
	            }

	            return function (cipher) {
	                return {
	                    encrypt: function (message, key, cfg) {
	                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
	                    },

	                    decrypt: function (ciphertext, key, cfg) {
	                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
	                    }
	                };
	            };
	        }())
	    });

	    /**
	     * Abstract base stream cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
	     */
	    var StreamCipher = C_lib.StreamCipher = Cipher.extend({
	        _doFinalize: function () {
	            // Process partial blocks
	            var finalProcessedBlocks = this._process(!!'flush');

	            return finalProcessedBlocks;
	        },

	        blockSize: 1
	    });

	    /**
	     * Mode namespace.
	     */
	    var C_mode = C.mode = {};

	    /**
	     * Abstract base block cipher mode template.
	     */
	    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
	        /**
	         * Creates this mode for encryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
	         */
	        createEncryptor: function (cipher, iv) {
	            return this.Encryptor.create(cipher, iv);
	        },

	        /**
	         * Creates this mode for decryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
	         */
	        createDecryptor: function (cipher, iv) {
	            return this.Decryptor.create(cipher, iv);
	        },

	        /**
	         * Initializes a newly created mode.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
	         */
	        init: function (cipher, iv) {
	            this._cipher = cipher;
	            this._iv = iv;
	        }
	    });

	    /**
	     * Cipher Block Chaining mode.
	     */
	    var CBC = C_mode.CBC = (function () {
	        /**
	         * Abstract base CBC mode.
	         */
	        var CBC = BlockCipherMode.extend();

	        /**
	         * CBC encryptor.
	         */
	        CBC.Encryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // XOR and encrypt
	                xorBlock.call(this, words, offset, blockSize);
	                cipher.encryptBlock(words, offset);

	                // Remember this block to use with next block
	                this._prevBlock = words.slice(offset, offset + blockSize);
	            }
	        });

	        /**
	         * CBC decryptor.
	         */
	        CBC.Decryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // Remember this block to use with next block
	                var thisBlock = words.slice(offset, offset + blockSize);

	                // Decrypt and XOR
	                cipher.decryptBlock(words, offset);
	                xorBlock.call(this, words, offset, blockSize);

	                // This block becomes the previous block
	                this._prevBlock = thisBlock;
	            }
	        });

	        function xorBlock(words, offset, blockSize) {
	            var block;

	            // Shortcut
	            var iv = this._iv;

	            // Choose mixing block
	            if (iv) {
	                block = iv;

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            } else {
	                block = this._prevBlock;
	            }

	            // XOR blocks
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= block[i];
	            }
	        }

	        return CBC;
	    }());

	    /**
	     * Padding namespace.
	     */
	    var C_pad = C.pad = {};

	    /**
	     * PKCS #5/7 padding strategy.
	     */
	    var Pkcs7 = C_pad.Pkcs7 = {
	        /**
	         * Pads data using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to pad.
	         * @param {number} blockSize The multiple that the data should be padded to.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
	         */
	        pad: function (data, blockSize) {
	            // Shortcut
	            var blockSizeBytes = blockSize * 4;

	            // Count padding bytes
	            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	            // Create padding word
	            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

	            // Create padding
	            var paddingWords = [];
	            for (var i = 0; i < nPaddingBytes; i += 4) {
	                paddingWords.push(paddingWord);
	            }
	            var padding = WordArray.create(paddingWords, nPaddingBytes);

	            // Add padding
	            data.concat(padding);
	        },

	        /**
	         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to unpad.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
	         */
	        unpad: function (data) {
	            // Get number of padding bytes from last byte
	            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	            // Remove padding
	            data.sigBytes -= nPaddingBytes;
	        }
	    };

	    /**
	     * Abstract base block cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
	     */
	    var BlockCipher = C_lib.BlockCipher = Cipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Mode} mode The block mode to use. Default: CBC
	         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
	         */
	        cfg: Cipher.cfg.extend({
	            mode: CBC,
	            padding: Pkcs7
	        }),

	        reset: function () {
	            var modeCreator;

	            // Reset cipher
	            Cipher.reset.call(this);

	            // Shortcuts
	            var cfg = this.cfg;
	            var iv = cfg.iv;
	            var mode = cfg.mode;

	            // Reset block mode
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                modeCreator = mode.createEncryptor;
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                modeCreator = mode.createDecryptor;
	                // Keep at least one block in the buffer for unpadding
	                this._minBufferSize = 1;
	            }

	            if (this._mode && this._mode.__creator == modeCreator) {
	                this._mode.init(this, iv && iv.words);
	            } else {
	                this._mode = modeCreator.call(mode, this, iv && iv.words);
	                this._mode.__creator = modeCreator;
	            }
	        },

	        _doProcessBlock: function (words, offset) {
	            this._mode.processBlock(words, offset);
	        },

	        _doFinalize: function () {
	            var finalProcessedBlocks;

	            // Shortcut
	            var padding = this.cfg.padding;

	            // Finalize
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                // Pad data
	                padding.pad(this._data, this.blockSize);

	                // Process final blocks
	                finalProcessedBlocks = this._process(!!'flush');
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                // Process final blocks
	                finalProcessedBlocks = this._process(!!'flush');

	                // Unpad data
	                padding.unpad(finalProcessedBlocks);
	            }

	            return finalProcessedBlocks;
	        },

	        blockSize: 128/32
	    });

	    /**
	     * A collection of cipher parameters.
	     *
	     * @property {WordArray} ciphertext The raw ciphertext.
	     * @property {WordArray} key The key to this ciphertext.
	     * @property {WordArray} iv The IV used in the ciphering operation.
	     * @property {WordArray} salt The salt used with a key derivation function.
	     * @property {Cipher} algorithm The cipher algorithm.
	     * @property {Mode} mode The block mode used in the ciphering operation.
	     * @property {Padding} padding The padding scheme used in the ciphering operation.
	     * @property {number} blockSize The block size of the cipher.
	     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
	     */
	    var CipherParams = C_lib.CipherParams = Base.extend({
	        /**
	         * Initializes a newly created cipher params object.
	         *
	         * @param {Object} cipherParams An object with any of the possible cipher parameters.
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.lib.CipherParams.create({
	         *         ciphertext: ciphertextWordArray,
	         *         key: keyWordArray,
	         *         iv: ivWordArray,
	         *         salt: saltWordArray,
	         *         algorithm: CryptoJS.algo.AES,
	         *         mode: CryptoJS.mode.CBC,
	         *         padding: CryptoJS.pad.PKCS7,
	         *         blockSize: 4,
	         *         formatter: CryptoJS.format.OpenSSL
	         *     });
	         */
	        init: function (cipherParams) {
	            this.mixIn(cipherParams);
	        },

	        /**
	         * Converts this cipher params object to a string.
	         *
	         * @param {Format} formatter (Optional) The formatting strategy to use.
	         *
	         * @return {string} The stringified cipher params.
	         *
	         * @throws Error If neither the formatter nor the default formatter is set.
	         *
	         * @example
	         *
	         *     var string = cipherParams + '';
	         *     var string = cipherParams.toString();
	         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
	         */
	        toString: function (formatter) {
	            return (formatter || this.formatter).stringify(this);
	        }
	    });

	    /**
	     * Format namespace.
	     */
	    var C_format = C.format = {};

	    /**
	     * OpenSSL formatting strategy.
	     */
	    var OpenSSLFormatter = C_format.OpenSSL = {
	        /**
	         * Converts a cipher params object to an OpenSSL-compatible string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The OpenSSL-compatible string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            var wordArray;

	            // Shortcuts
	            var ciphertext = cipherParams.ciphertext;
	            var salt = cipherParams.salt;

	            // Format
	            if (salt) {
	                wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
	            } else {
	                wordArray = ciphertext;
	            }

	            return wordArray.toString(Base64);
	        },

	        /**
	         * Converts an OpenSSL-compatible string to a cipher params object.
	         *
	         * @param {string} openSSLStr The OpenSSL-compatible string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
	         */
	        parse: function (openSSLStr) {
	            var salt;

	            // Parse base64
	            var ciphertext = Base64.parse(openSSLStr);

	            // Shortcut
	            var ciphertextWords = ciphertext.words;

	            // Test for salt
	            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
	                // Extract salt
	                salt = WordArray.create(ciphertextWords.slice(2, 4));

	                // Remove salt from ciphertext
	                ciphertextWords.splice(0, 4);
	                ciphertext.sigBytes -= 16;
	            }

	            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
	        }
	    };

	    /**
	     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
	     */
	    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
	         */
	        cfg: Base.extend({
	            format: OpenSSLFormatter
	        }),

	        /**
	         * Encrypts a message.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Encrypt
	            var encryptor = cipher.createEncryptor(key, cfg);
	            var ciphertext = encryptor.finalize(message);

	            // Shortcut
	            var cipherCfg = encryptor.cfg;

	            // Create and return serializable cipher params
	            return CipherParams.create({
	                ciphertext: ciphertext,
	                key: key,
	                iv: cipherCfg.iv,
	                algorithm: cipher,
	                mode: cipherCfg.mode,
	                padding: cipherCfg.padding,
	                blockSize: cipher.blockSize,
	                formatter: cfg.format
	            });
	        },

	        /**
	         * Decrypts serialized ciphertext.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Decrypt
	            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

	            return plaintext;
	        },

	        /**
	         * Converts serialized ciphertext to CipherParams,
	         * else assumed CipherParams already and returns ciphertext unchanged.
	         *
	         * @param {CipherParams|string} ciphertext The ciphertext.
	         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
	         *
	         * @return {CipherParams} The unserialized ciphertext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
	         */
	        _parse: function (ciphertext, format) {
	            if (typeof ciphertext == 'string') {
	                return format.parse(ciphertext, this);
	            } else {
	                return ciphertext;
	            }
	        }
	    });

	    /**
	     * Key derivation function namespace.
	     */
	    var C_kdf = C.kdf = {};

	    /**
	     * OpenSSL key derivation function.
	     */
	    var OpenSSLKdf = C_kdf.OpenSSL = {
	        /**
	         * Derives a key and IV from a password.
	         *
	         * @param {string} password The password to derive from.
	         * @param {number} keySize The size in words of the key to generate.
	         * @param {number} ivSize The size in words of the IV to generate.
	         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	         *
	         * @return {CipherParams} A cipher params object with the key, IV, and salt.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
	         */
	        execute: function (password, keySize, ivSize, salt, hasher) {
	            // Generate random salt
	            if (!salt) {
	                salt = WordArray.random(64/8);
	            }

	            // Derive key and IV
	            if (!hasher) {
	                var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);
	            } else {
	                var key = EvpKDF.create({ keySize: keySize + ivSize, hasher: hasher }).compute(password, salt);
	            }


	            // Separate key and IV
	            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
	            key.sigBytes = keySize * 4;

	            // Return params
	            return CipherParams.create({ key: key, iv: iv, salt: salt });
	        }
	    };

	    /**
	     * A serializable cipher wrapper that derives the key from a password,
	     * and returns ciphertext as a serializable cipher params object.
	     */
	    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
	         */
	        cfg: SerializableCipher.cfg.extend({
	            kdf: OpenSSLKdf
	        }),

	        /**
	         * Encrypts a message using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, cfg.salt, cfg.hasher);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Encrypt
	            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

	            // Mix in derived params
	            ciphertext.mixIn(derivedParams);

	            return ciphertext;
	        },

	        /**
	         * Decrypts serialized ciphertext using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt, cfg.hasher);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Decrypt
	            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

	            return plaintext;
	        }
	    });
	}());


}));

/***/ }),

/***/ 8249:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory();
	}
	else {}
}(this, function () {

	/*globals window, global, require*/

	/**
	 * CryptoJS core components.
	 */
	var CryptoJS = CryptoJS || (function (Math, undefined) {

	    var crypto;

	    // Native crypto from window (Browser)
	    if (typeof window !== 'undefined' && window.crypto) {
	        crypto = window.crypto;
	    }

	    // Native crypto in web worker (Browser)
	    if (typeof self !== 'undefined' && self.crypto) {
	        crypto = self.crypto;
	    }

	    // Native crypto from worker
	    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
	        crypto = globalThis.crypto;
	    }

	    // Native (experimental IE 11) crypto from window (Browser)
	    if (!crypto && typeof window !== 'undefined' && window.msCrypto) {
	        crypto = window.msCrypto;
	    }

	    // Native crypto from global (NodeJS)
	    if (!crypto && typeof __webpack_require__.g !== 'undefined' && __webpack_require__.g.crypto) {
	        crypto = __webpack_require__.g.crypto;
	    }

	    // Native crypto import via require (NodeJS)
	    if (!crypto && "function" === 'function') {
	        try {
	            crypto = __webpack_require__(2480);
	        } catch (err) {}
	    }

	    /*
	     * Cryptographically secure pseudorandom number generator
	     *
	     * As Math.random() is cryptographically not safe to use
	     */
	    var cryptoSecureRandomInt = function () {
	        if (crypto) {
	            // Use getRandomValues method (Browser)
	            if (typeof crypto.getRandomValues === 'function') {
	                try {
	                    return crypto.getRandomValues(new Uint32Array(1))[0];
	                } catch (err) {}
	            }

	            // Use randomBytes method (NodeJS)
	            if (typeof crypto.randomBytes === 'function') {
	                try {
	                    return crypto.randomBytes(4).readInt32LE();
	                } catch (err) {}
	            }
	        }

	        throw new Error('Native crypto module could not be used to get secure random number.');
	    };

	    /*
	     * Local polyfill of Object.create

	     */
	    var create = Object.create || (function () {
	        function F() {}

	        return function (obj) {
	            var subtype;

	            F.prototype = obj;

	            subtype = new F();

	            F.prototype = null;

	            return subtype;
	        };
	    }());

	    /**
	     * CryptoJS namespace.
	     */
	    var C = {};

	    /**
	     * Library namespace.
	     */
	    var C_lib = C.lib = {};

	    /**
	     * Base object for prototypal inheritance.
	     */
	    var Base = C_lib.Base = (function () {


	        return {
	            /**
	             * Creates a new object that inherits from this object.
	             *
	             * @param {Object} overrides Properties to copy into the new object.
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         field: 'value',
	             *
	             *         method: function () {
	             *         }
	             *     });
	             */
	            extend: function (overrides) {
	                // Spawn
	                var subtype = create(this);

	                // Augment
	                if (overrides) {
	                    subtype.mixIn(overrides);
	                }

	                // Create default initializer
	                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
	                    subtype.init = function () {
	                        subtype.$super.init.apply(this, arguments);
	                    };
	                }

	                // Initializer's prototype is the subtype object
	                subtype.init.prototype = subtype;

	                // Reference supertype
	                subtype.$super = this;

	                return subtype;
	            },

	            /**
	             * Extends this object and runs the init method.
	             * Arguments to create() will be passed to init().
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var instance = MyType.create();
	             */
	            create: function () {
	                var instance = this.extend();
	                instance.init.apply(instance, arguments);

	                return instance;
	            },

	            /**
	             * Initializes a newly created object.
	             * Override this method to add some logic when your objects are created.
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         init: function () {
	             *             // ...
	             *         }
	             *     });
	             */
	            init: function () {
	            },

	            /**
	             * Copies properties into this object.
	             *
	             * @param {Object} properties The properties to mix in.
	             *
	             * @example
	             *
	             *     MyType.mixIn({
	             *         field: 'value'
	             *     });
	             */
	            mixIn: function (properties) {
	                for (var propertyName in properties) {
	                    if (properties.hasOwnProperty(propertyName)) {
	                        this[propertyName] = properties[propertyName];
	                    }
	                }

	                // IE won't copy toString using the loop above
	                if (properties.hasOwnProperty('toString')) {
	                    this.toString = properties.toString;
	                }
	            },

	            /**
	             * Creates a copy of this object.
	             *
	             * @return {Object} The clone.
	             *
	             * @example
	             *
	             *     var clone = instance.clone();
	             */
	            clone: function () {
	                return this.init.prototype.extend(this);
	            }
	        };
	    }());

	    /**
	     * An array of 32-bit words.
	     *
	     * @property {Array} words The array of 32-bit words.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var WordArray = C_lib.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of 32-bit words.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.create();
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 4;
	            }
	        },

	        /**
	         * Converts this word array to a string.
	         *
	         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
	         *
	         * @return {string} The stringified word array.
	         *
	         * @example
	         *
	         *     var string = wordArray + '';
	         *     var string = wordArray.toString();
	         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
	         */
	        toString: function (encoder) {
	            return (encoder || Hex).stringify(this);
	        },

	        /**
	         * Concatenates a word array to this word array.
	         *
	         * @param {WordArray} wordArray The word array to append.
	         *
	         * @return {WordArray} This word array.
	         *
	         * @example
	         *
	         *     wordArray1.concat(wordArray2);
	         */
	        concat: function (wordArray) {
	            // Shortcuts
	            var thisWords = this.words;
	            var thatWords = wordArray.words;
	            var thisSigBytes = this.sigBytes;
	            var thatSigBytes = wordArray.sigBytes;

	            // Clamp excess bits
	            this.clamp();

	            // Concat
	            if (thisSigBytes % 4) {
	                // Copy one byte at a time
	                for (var i = 0; i < thatSigBytes; i++) {
	                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
	                }
	            } else {
	                // Copy one word at a time
	                for (var j = 0; j < thatSigBytes; j += 4) {
	                    thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
	                }
	            }
	            this.sigBytes += thatSigBytes;

	            // Chainable
	            return this;
	        },

	        /**
	         * Removes insignificant bits.
	         *
	         * @example
	         *
	         *     wordArray.clamp();
	         */
	        clamp: function () {
	            // Shortcuts
	            var words = this.words;
	            var sigBytes = this.sigBytes;

	            // Clamp
	            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
	            words.length = Math.ceil(sigBytes / 4);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = wordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone.words = this.words.slice(0);

	            return clone;
	        },

	        /**
	         * Creates a word array filled with random bytes.
	         *
	         * @param {number} nBytes The number of random bytes to generate.
	         *
	         * @return {WordArray} The random word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.random(16);
	         */
	        random: function (nBytes) {
	            var words = [];

	            for (var i = 0; i < nBytes; i += 4) {
	                words.push(cryptoSecureRandomInt());
	            }

	            return new WordArray.init(words, nBytes);
	        }
	    });

	    /**
	     * Encoder namespace.
	     */
	    var C_enc = C.enc = {};

	    /**
	     * Hex encoding strategy.
	     */
	    var Hex = C_enc.Hex = {
	        /**
	         * Converts a word array to a hex string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The hex string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var hexChars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                hexChars.push((bite >>> 4).toString(16));
	                hexChars.push((bite & 0x0f).toString(16));
	            }

	            return hexChars.join('');
	        },

	        /**
	         * Converts a hex string to a word array.
	         *
	         * @param {string} hexStr The hex string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
	         */
	        parse: function (hexStr) {
	            // Shortcut
	            var hexStrLength = hexStr.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < hexStrLength; i += 2) {
	                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
	            }

	            return new WordArray.init(words, hexStrLength / 2);
	        }
	    };

	    /**
	     * Latin1 encoding strategy.
	     */
	    var Latin1 = C_enc.Latin1 = {
	        /**
	         * Converts a word array to a Latin1 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Latin1 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var latin1Chars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                latin1Chars.push(String.fromCharCode(bite));
	            }

	            return latin1Chars.join('');
	        },

	        /**
	         * Converts a Latin1 string to a word array.
	         *
	         * @param {string} latin1Str The Latin1 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
	         */
	        parse: function (latin1Str) {
	            // Shortcut
	            var latin1StrLength = latin1Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < latin1StrLength; i++) {
	                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
	            }

	            return new WordArray.init(words, latin1StrLength);
	        }
	    };

	    /**
	     * UTF-8 encoding strategy.
	     */
	    var Utf8 = C_enc.Utf8 = {
	        /**
	         * Converts a word array to a UTF-8 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-8 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            try {
	                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
	            } catch (e) {
	                throw new Error('Malformed UTF-8 data');
	            }
	        },

	        /**
	         * Converts a UTF-8 string to a word array.
	         *
	         * @param {string} utf8Str The UTF-8 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
	         */
	        parse: function (utf8Str) {
	            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
	        }
	    };

	    /**
	     * Abstract buffered block algorithm template.
	     *
	     * The property blockSize must be implemented in a concrete subtype.
	     *
	     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
	     */
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
	        /**
	         * Resets this block algorithm's data buffer to its initial state.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm.reset();
	         */
	        reset: function () {
	            // Initial values
	            this._data = new WordArray.init();
	            this._nDataBytes = 0;
	        },

	        /**
	         * Adds new data to this block algorithm's buffer.
	         *
	         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm._append('data');
	         *     bufferedBlockAlgorithm._append(wordArray);
	         */
	        _append: function (data) {
	            // Convert string to WordArray, else assume WordArray already
	            if (typeof data == 'string') {
	                data = Utf8.parse(data);
	            }

	            // Append
	            this._data.concat(data);
	            this._nDataBytes += data.sigBytes;
	        },

	        /**
	         * Processes available data blocks.
	         *
	         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	         *
	         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
	         *
	         * @return {WordArray} The processed data.
	         *
	         * @example
	         *
	         *     var processedData = bufferedBlockAlgorithm._process();
	         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
	         */
	        _process: function (doFlush) {
	            var processedWords;

	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var dataSigBytes = data.sigBytes;
	            var blockSize = this.blockSize;
	            var blockSizeBytes = blockSize * 4;

	            // Count blocks ready
	            var nBlocksReady = dataSigBytes / blockSizeBytes;
	            if (doFlush) {
	                // Round up to include partial blocks
	                nBlocksReady = Math.ceil(nBlocksReady);
	            } else {
	                // Round down to include only full blocks,
	                // less the number of blocks that must remain in the buffer
	                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
	            }

	            // Count words ready
	            var nWordsReady = nBlocksReady * blockSize;

	            // Count bytes ready
	            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

	            // Process blocks
	            if (nWordsReady) {
	                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
	                    // Perform concrete-algorithm logic
	                    this._doProcessBlock(dataWords, offset);
	                }

	                // Remove processed words
	                processedWords = dataWords.splice(0, nWordsReady);
	                data.sigBytes -= nBytesReady;
	            }

	            // Return processed words
	            return new WordArray.init(processedWords, nBytesReady);
	        },

	        /**
	         * Creates a copy of this object.
	         *
	         * @return {Object} The clone.
	         *
	         * @example
	         *
	         *     var clone = bufferedBlockAlgorithm.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone._data = this._data.clone();

	            return clone;
	        },

	        _minBufferSize: 0
	    });

	    /**
	     * Abstract hasher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
	     */
	    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         */
	        cfg: Base.extend(),

	        /**
	         * Initializes a newly created hasher.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
	         *
	         * @example
	         *
	         *     var hasher = CryptoJS.algo.SHA256.create();
	         */
	        init: function (cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this hasher to its initial state.
	         *
	         * @example
	         *
	         *     hasher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-hasher logic
	            this._doReset();
	        },

	        /**
	         * Updates this hasher with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {Hasher} This hasher.
	         *
	         * @example
	         *
	         *     hasher.update('message');
	         *     hasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            // Append
	            this._append(messageUpdate);

	            // Update the hash
	            this._process();

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the hash computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The hash.
	         *
	         * @example
	         *
	         *     var hash = hasher.finalize();
	         *     var hash = hasher.finalize('message');
	         *     var hash = hasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Final message update
	            if (messageUpdate) {
	                this._append(messageUpdate);
	            }

	            // Perform concrete-hasher logic
	            var hash = this._doFinalize();

	            return hash;
	        },

	        blockSize: 512/32,

	        /**
	         * Creates a shortcut function to a hasher's object interface.
	         *
	         * @param {Hasher} hasher The hasher to create a helper for.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
	         */
	        _createHelper: function (hasher) {
	            return function (message, cfg) {
	                return new hasher.init(cfg).finalize(message);
	            };
	        },

	        /**
	         * Creates a shortcut function to the HMAC's object interface.
	         *
	         * @param {Hasher} hasher The hasher to use in this HMAC helper.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
	         */
	        _createHmacHelper: function (hasher) {
	            return function (message, key) {
	                return new C_algo.HMAC.init(hasher, key).finalize(message);
	            };
	        }
	    });

	    /**
	     * Algorithm namespace.
	     */
	    var C_algo = C.algo = {};

	    return C;
	}(Math));


	return CryptoJS;

}));

/***/ }),

/***/ 8269:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64 encoding strategy.
	     */
	    var Base64 = C_enc.Base64 = {
	        /**
	         * Converts a word array to a Base64 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Base64 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64 string to a word array.
	         *
	         * @param {string} base64Str The Base64 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
	         */
	        parse: function (base64Str) {
	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                    reverseMap = this._reverseMap = [];
	                    for (var j = 0; j < map.length; j++) {
	                        reverseMap[map.charCodeAt(j)] = j;
	                    }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	      var words = [];
	      var nBytes = 0;
	      for (var i = 0; i < base64StrLength; i++) {
	          if (i % 4) {
	              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	              var bitsCombined = bits1 | bits2;
	              words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
	              nBytes++;
	          }
	      }
	      return WordArray.create(words, nBytes);
	    }
	}());


	return CryptoJS.enc.Base64;

}));

/***/ }),

/***/ 3786:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64url encoding strategy.
	     */
	    var Base64url = C_enc.Base64url = {
	        /**
	         * Converts a word array to a Base64url string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @param {boolean} urlSafe Whether to use url safe
	         *
	         * @return {string} The Base64url string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64url.stringify(wordArray);
	         */
	        stringify: function (wordArray, urlSafe) {
	            if (urlSafe === undefined) {
	                urlSafe = true
	            }
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = urlSafe ? this._safe_map : this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64url string to a word array.
	         *
	         * @param {string} base64Str The Base64url string.
	         *
	         * @param {boolean} urlSafe Whether to use url safe
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64url.parse(base64String);
	         */
	        parse: function (base64Str, urlSafe) {
	            if (urlSafe === undefined) {
	                urlSafe = true
	            }

	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = urlSafe ? this._safe_map : this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                reverseMap = this._reverseMap = [];
	                for (var j = 0; j < map.length; j++) {
	                    reverseMap[map.charCodeAt(j)] = j;
	                }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
	        _safe_map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	        var words = [];
	        var nBytes = 0;
	        for (var i = 0; i < base64StrLength; i++) {
	            if (i % 4) {
	                var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	                var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	                var bitsCombined = bits1 | bits2;
	                words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
	                nBytes++;
	            }
	        }
	        return WordArray.create(words, nBytes);
	    }
	}());


	return CryptoJS.enc.Base64url;

}));

/***/ }),

/***/ 298:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * UTF-16 BE encoding strategy.
	     */
	    var Utf16BE = C_enc.Utf16 = C_enc.Utf16BE = {
	        /**
	         * Converts a word array to a UTF-16 BE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 BE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 BE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 BE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16.parse(utf16String);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    /**
	     * UTF-16 LE encoding strategy.
	     */
	    C_enc.Utf16LE = {
	        /**
	         * Converts a word array to a UTF-16 LE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 LE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 LE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 LE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    function swapEndian(word) {
	        return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
	    }
	}());


	return CryptoJS.enc.Utf16;

}));

/***/ }),

/***/ 888:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(2783), __webpack_require__(9824));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var MD5 = C_algo.MD5;

	    /**
	     * This key derivation function is meant to conform with EVP_BytesToKey.
	     * www.openssl.org/docs/crypto/EVP_BytesToKey.html
	     */
	    var EvpKDF = C_algo.EvpKDF = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hash algorithm to use. Default: MD5
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: MD5,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.EvpKDF.create();
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Derives a key from a password.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            var block;

	            // Shortcut
	            var cfg = this.cfg;

	            // Init hasher
	            var hasher = cfg.hasher.create();

	            // Initial values
	            var derivedKey = WordArray.create();

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                if (block) {
	                    hasher.update(block);
	                }
	                block = hasher.update(password).finalize(salt);
	                hasher.reset();

	                // Iterations
	                for (var i = 1; i < iterations; i++) {
	                    block = hasher.finalize(block);
	                    hasher.reset();
	                }

	                derivedKey.concat(block);
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Derives a key from a password.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.EvpKDF(password, salt);
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.EvpKDF = function (password, salt, cfg) {
	        return EvpKDF.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.EvpKDF;

}));

/***/ }),

/***/ 2209:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var CipherParams = C_lib.CipherParams;
	    var C_enc = C.enc;
	    var Hex = C_enc.Hex;
	    var C_format = C.format;

	    var HexFormatter = C_format.Hex = {
	        /**
	         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The hexadecimally encoded string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            return cipherParams.ciphertext.toString(Hex);
	        },

	        /**
	         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
	         *
	         * @param {string} input The hexadecimally encoded string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
	         */
	        parse: function (input) {
	            var ciphertext = Hex.parse(input);
	            return CipherParams.create({ ciphertext: ciphertext });
	        }
	    };
	}());


	return CryptoJS.format.Hex;

}));

/***/ }),

/***/ 9824:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var C_algo = C.algo;

	    /**
	     * HMAC algorithm.
	     */
	    var HMAC = C_algo.HMAC = Base.extend({
	        /**
	         * Initializes a newly created HMAC.
	         *
	         * @param {Hasher} hasher The hash algorithm to use.
	         * @param {WordArray|string} key The secret key.
	         *
	         * @example
	         *
	         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
	         */
	        init: function (hasher, key) {
	            // Init hasher
	            hasher = this._hasher = new hasher.init();

	            // Convert string to WordArray, else assume WordArray already
	            if (typeof key == 'string') {
	                key = Utf8.parse(key);
	            }

	            // Shortcuts
	            var hasherBlockSize = hasher.blockSize;
	            var hasherBlockSizeBytes = hasherBlockSize * 4;

	            // Allow arbitrary length keys
	            if (key.sigBytes > hasherBlockSizeBytes) {
	                key = hasher.finalize(key);
	            }

	            // Clamp excess bits
	            key.clamp();

	            // Clone key for inner and outer pads
	            var oKey = this._oKey = key.clone();
	            var iKey = this._iKey = key.clone();

	            // Shortcuts
	            var oKeyWords = oKey.words;
	            var iKeyWords = iKey.words;

	            // XOR keys with pad constants
	            for (var i = 0; i < hasherBlockSize; i++) {
	                oKeyWords[i] ^= 0x5c5c5c5c;
	                iKeyWords[i] ^= 0x36363636;
	            }
	            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this HMAC to its initial state.
	         *
	         * @example
	         *
	         *     hmacHasher.reset();
	         */
	        reset: function () {
	            // Shortcut
	            var hasher = this._hasher;

	            // Reset
	            hasher.reset();
	            hasher.update(this._iKey);
	        },

	        /**
	         * Updates this HMAC with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {HMAC} This HMAC instance.
	         *
	         * @example
	         *
	         *     hmacHasher.update('message');
	         *     hmacHasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            this._hasher.update(messageUpdate);

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the HMAC computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The HMAC.
	         *
	         * @example
	         *
	         *     var hmac = hmacHasher.finalize();
	         *     var hmac = hmacHasher.finalize('message');
	         *     var hmac = hmacHasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Shortcut
	            var hasher = this._hasher;

	            // Compute HMAC
	            var innerHash = hasher.finalize(messageUpdate);
	            hasher.reset();
	            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

	            return hmac;
	        }
	    });
	}());


}));

/***/ }),

/***/ 1354:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(4938), __webpack_require__(4433), __webpack_require__(298), __webpack_require__(8269), __webpack_require__(3786), __webpack_require__(8214), __webpack_require__(2783), __webpack_require__(2153), __webpack_require__(7792), __webpack_require__(34), __webpack_require__(7460), __webpack_require__(3327), __webpack_require__(706), __webpack_require__(9824), __webpack_require__(2112), __webpack_require__(888), __webpack_require__(5109), __webpack_require__(8568), __webpack_require__(4242), __webpack_require__(9968), __webpack_require__(7660), __webpack_require__(1148), __webpack_require__(3615), __webpack_require__(2807), __webpack_require__(1077), __webpack_require__(6475), __webpack_require__(6991), __webpack_require__(2209), __webpack_require__(452), __webpack_require__(4253), __webpack_require__(1857), __webpack_require__(4454), __webpack_require__(3974), __webpack_require__(7407));
	}
	else {}
}(this, function (CryptoJS) {

	return CryptoJS;

}));

/***/ }),

/***/ 4433:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Check if typed arrays are supported
	    if (typeof ArrayBuffer != 'function') {
	        return;
	    }

	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;

	    // Reference original init
	    var superInit = WordArray.init;

	    // Augment WordArray.init to handle typed arrays
	    var subInit = WordArray.init = function (typedArray) {
	        // Convert buffers to uint8
	        if (typedArray instanceof ArrayBuffer) {
	            typedArray = new Uint8Array(typedArray);
	        }

	        // Convert other array views to uint8
	        if (
	            typedArray instanceof Int8Array ||
	            (typeof Uint8ClampedArray !== "undefined" && typedArray instanceof Uint8ClampedArray) ||
	            typedArray instanceof Int16Array ||
	            typedArray instanceof Uint16Array ||
	            typedArray instanceof Int32Array ||
	            typedArray instanceof Uint32Array ||
	            typedArray instanceof Float32Array ||
	            typedArray instanceof Float64Array
	        ) {
	            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
	        }

	        // Handle Uint8Array
	        if (typedArray instanceof Uint8Array) {
	            // Shortcut
	            var typedArrayByteLength = typedArray.byteLength;

	            // Extract bytes
	            var words = [];
	            for (var i = 0; i < typedArrayByteLength; i++) {
	                words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
	            }

	            // Initialize this word array
	            superInit.call(this, words, typedArrayByteLength);
	        } else {
	            // Else call normal init
	            superInit.apply(this, arguments);
	        }
	    };

	    subInit.prototype = WordArray;
	}());


	return CryptoJS.lib.WordArray;

}));

/***/ }),

/***/ 8214:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var T = [];

	    // Compute constants
	    (function () {
	        for (var i = 0; i < 64; i++) {
	            T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
	        }
	    }());

	    /**
	     * MD5 hash algorithm.
	     */
	    var MD5 = C_algo.MD5 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }

	            // Shortcuts
	            var H = this._hash.words;

	            var M_offset_0  = M[offset + 0];
	            var M_offset_1  = M[offset + 1];
	            var M_offset_2  = M[offset + 2];
	            var M_offset_3  = M[offset + 3];
	            var M_offset_4  = M[offset + 4];
	            var M_offset_5  = M[offset + 5];
	            var M_offset_6  = M[offset + 6];
	            var M_offset_7  = M[offset + 7];
	            var M_offset_8  = M[offset + 8];
	            var M_offset_9  = M[offset + 9];
	            var M_offset_10 = M[offset + 10];
	            var M_offset_11 = M[offset + 11];
	            var M_offset_12 = M[offset + 12];
	            var M_offset_13 = M[offset + 13];
	            var M_offset_14 = M[offset + 14];
	            var M_offset_15 = M[offset + 15];

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];

	            // Computation
	            a = FF(a, b, c, d, M_offset_0,  7,  T[0]);
	            d = FF(d, a, b, c, M_offset_1,  12, T[1]);
	            c = FF(c, d, a, b, M_offset_2,  17, T[2]);
	            b = FF(b, c, d, a, M_offset_3,  22, T[3]);
	            a = FF(a, b, c, d, M_offset_4,  7,  T[4]);
	            d = FF(d, a, b, c, M_offset_5,  12, T[5]);
	            c = FF(c, d, a, b, M_offset_6,  17, T[6]);
	            b = FF(b, c, d, a, M_offset_7,  22, T[7]);
	            a = FF(a, b, c, d, M_offset_8,  7,  T[8]);
	            d = FF(d, a, b, c, M_offset_9,  12, T[9]);
	            c = FF(c, d, a, b, M_offset_10, 17, T[10]);
	            b = FF(b, c, d, a, M_offset_11, 22, T[11]);
	            a = FF(a, b, c, d, M_offset_12, 7,  T[12]);
	            d = FF(d, a, b, c, M_offset_13, 12, T[13]);
	            c = FF(c, d, a, b, M_offset_14, 17, T[14]);
	            b = FF(b, c, d, a, M_offset_15, 22, T[15]);

	            a = GG(a, b, c, d, M_offset_1,  5,  T[16]);
	            d = GG(d, a, b, c, M_offset_6,  9,  T[17]);
	            c = GG(c, d, a, b, M_offset_11, 14, T[18]);
	            b = GG(b, c, d, a, M_offset_0,  20, T[19]);
	            a = GG(a, b, c, d, M_offset_5,  5,  T[20]);
	            d = GG(d, a, b, c, M_offset_10, 9,  T[21]);
	            c = GG(c, d, a, b, M_offset_15, 14, T[22]);
	            b = GG(b, c, d, a, M_offset_4,  20, T[23]);
	            a = GG(a, b, c, d, M_offset_9,  5,  T[24]);
	            d = GG(d, a, b, c, M_offset_14, 9,  T[25]);
	            c = GG(c, d, a, b, M_offset_3,  14, T[26]);
	            b = GG(b, c, d, a, M_offset_8,  20, T[27]);
	            a = GG(a, b, c, d, M_offset_13, 5,  T[28]);
	            d = GG(d, a, b, c, M_offset_2,  9,  T[29]);
	            c = GG(c, d, a, b, M_offset_7,  14, T[30]);
	            b = GG(b, c, d, a, M_offset_12, 20, T[31]);

	            a = HH(a, b, c, d, M_offset_5,  4,  T[32]);
	            d = HH(d, a, b, c, M_offset_8,  11, T[33]);
	            c = HH(c, d, a, b, M_offset_11, 16, T[34]);
	            b = HH(b, c, d, a, M_offset_14, 23, T[35]);
	            a = HH(a, b, c, d, M_offset_1,  4,  T[36]);
	            d = HH(d, a, b, c, M_offset_4,  11, T[37]);
	            c = HH(c, d, a, b, M_offset_7,  16, T[38]);
	            b = HH(b, c, d, a, M_offset_10, 23, T[39]);
	            a = HH(a, b, c, d, M_offset_13, 4,  T[40]);
	            d = HH(d, a, b, c, M_offset_0,  11, T[41]);
	            c = HH(c, d, a, b, M_offset_3,  16, T[42]);
	            b = HH(b, c, d, a, M_offset_6,  23, T[43]);
	            a = HH(a, b, c, d, M_offset_9,  4,  T[44]);
	            d = HH(d, a, b, c, M_offset_12, 11, T[45]);
	            c = HH(c, d, a, b, M_offset_15, 16, T[46]);
	            b = HH(b, c, d, a, M_offset_2,  23, T[47]);

	            a = II(a, b, c, d, M_offset_0,  6,  T[48]);
	            d = II(d, a, b, c, M_offset_7,  10, T[49]);
	            c = II(c, d, a, b, M_offset_14, 15, T[50]);
	            b = II(b, c, d, a, M_offset_5,  21, T[51]);
	            a = II(a, b, c, d, M_offset_12, 6,  T[52]);
	            d = II(d, a, b, c, M_offset_3,  10, T[53]);
	            c = II(c, d, a, b, M_offset_10, 15, T[54]);
	            b = II(b, c, d, a, M_offset_1,  21, T[55]);
	            a = II(a, b, c, d, M_offset_8,  6,  T[56]);
	            d = II(d, a, b, c, M_offset_15, 10, T[57]);
	            c = II(c, d, a, b, M_offset_6,  15, T[58]);
	            b = II(b, c, d, a, M_offset_13, 21, T[59]);
	            a = II(a, b, c, d, M_offset_4,  6,  T[60]);
	            d = II(d, a, b, c, M_offset_11, 10, T[61]);
	            c = II(c, d, a, b, M_offset_2,  15, T[62]);
	            b = II(b, c, d, a, M_offset_9,  21, T[63]);

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

	            var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
	            var nBitsTotalL = nBitsTotal;
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
	                (((nBitsTotalH << 8)  | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalH << 24) | (nBitsTotalH >>> 8))  & 0xff00ff00)
	            );
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotalL << 8)  | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalL << 24) | (nBitsTotalL >>> 8))  & 0xff00ff00)
	            );

	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                // Shortcut
	                var H_i = H[i];

	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    function FF(a, b, c, d, x, s, t) {
	        var n = a + ((b & c) | (~b & d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function GG(a, b, c, d, x, s, t) {
	        var n = a + ((b & d) | (c & ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function HH(a, b, c, d, x, s, t) {
	        var n = a + (b ^ c ^ d) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function II(a, b, c, d, x, s, t) {
	        var n = a + (c ^ (b | ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.MD5('message');
	     *     var hash = CryptoJS.MD5(wordArray);
	     */
	    C.MD5 = Hasher._createHelper(MD5);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacMD5(message, key);
	     */
	    C.HmacMD5 = Hasher._createHmacHelper(MD5);
	}(Math));


	return CryptoJS.MD5;

}));

/***/ }),

/***/ 8568:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Cipher Feedback block mode.
	 */
	CryptoJS.mode.CFB = (function () {
	    var CFB = CryptoJS.lib.BlockCipherMode.extend();

	    CFB.Encryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // Remember this block to use with next block
	            this._prevBlock = words.slice(offset, offset + blockSize);
	        }
	    });

	    CFB.Decryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            // Remember this block to use with next block
	            var thisBlock = words.slice(offset, offset + blockSize);

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // This block becomes the previous block
	            this._prevBlock = thisBlock;
	        }
	    });

	    function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
	        var keystream;

	        // Shortcut
	        var iv = this._iv;

	        // Generate keystream
	        if (iv) {
	            keystream = iv.slice(0);

	            // Remove IV for subsequent blocks
	            this._iv = undefined;
	        } else {
	            keystream = this._prevBlock;
	        }
	        cipher.encryptBlock(keystream, 0);

	        // Encrypt
	        for (var i = 0; i < blockSize; i++) {
	            words[offset + i] ^= keystream[i];
	        }
	    }

	    return CFB;
	}());


	return CryptoJS.mode.CFB;

}));

/***/ }),

/***/ 9968:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/** @preserve
	 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
	 * derived from CryptoJS.mode.CTR
	 * Jan Hruby jhruby.web@gmail.com
	 */
	CryptoJS.mode.CTRGladman = (function () {
	    var CTRGladman = CryptoJS.lib.BlockCipherMode.extend();

		function incWord(word)
		{
			if (((word >> 24) & 0xff) === 0xff) { //overflow
			var b1 = (word >> 16)&0xff;
			var b2 = (word >> 8)&0xff;
			var b3 = word & 0xff;

			if (b1 === 0xff) // overflow b1
			{
			b1 = 0;
			if (b2 === 0xff)
			{
				b2 = 0;
				if (b3 === 0xff)
				{
					b3 = 0;
				}
				else
				{
					++b3;
				}
			}
			else
			{
				++b2;
			}
			}
			else
			{
			++b1;
			}

			word = 0;
			word += (b1 << 16);
			word += (b2 << 8);
			word += b3;
			}
			else
			{
			word += (0x01 << 24);
			}
			return word;
		}

		function incCounter(counter)
		{
			if ((counter[0] = incWord(counter[0])) === 0)
			{
				// encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
				counter[1] = incWord(counter[1]);
			}
			return counter;
		}

	    var Encryptor = CTRGladman.Encryptor = CTRGladman.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }

				incCounter(counter);

				var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTRGladman.Decryptor = Encryptor;

	    return CTRGladman;
	}());




	return CryptoJS.mode.CTRGladman;

}));

/***/ }),

/***/ 4242:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Counter block mode.
	 */
	CryptoJS.mode.CTR = (function () {
	    var CTR = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = CTR.Encryptor = CTR.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Increment counter
	            counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTR.Decryptor = Encryptor;

	    return CTR;
	}());


	return CryptoJS.mode.CTR;

}));

/***/ }),

/***/ 1148:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Electronic Codebook block mode.
	 */
	CryptoJS.mode.ECB = (function () {
	    var ECB = CryptoJS.lib.BlockCipherMode.extend();

	    ECB.Encryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.encryptBlock(words, offset);
	        }
	    });

	    ECB.Decryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.decryptBlock(words, offset);
	        }
	    });

	    return ECB;
	}());


	return CryptoJS.mode.ECB;

}));

/***/ }),

/***/ 7660:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Output Feedback block mode.
	 */
	CryptoJS.mode.OFB = (function () {
	    var OFB = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = OFB.Encryptor = OFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var keystream = this._keystream;

	            // Generate keystream
	            if (iv) {
	                keystream = this._keystream = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    OFB.Decryptor = Encryptor;

	    return OFB;
	}());


	return CryptoJS.mode.OFB;

}));

/***/ }),

/***/ 3615:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * ANSI X.923 padding strategy.
	 */
	CryptoJS.pad.AnsiX923 = {
	    pad: function (data, blockSize) {
	        // Shortcuts
	        var dataSigBytes = data.sigBytes;
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

	        // Compute last byte position
	        var lastBytePos = dataSigBytes + nPaddingBytes - 1;

	        // Pad
	        data.clamp();
	        data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
	        data.sigBytes += nPaddingBytes;
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	return CryptoJS.pad.Ansix923;

}));

/***/ }),

/***/ 2807:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * ISO 10126 padding strategy.
	 */
	CryptoJS.pad.Iso10126 = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	        // Pad
	        data.concat(CryptoJS.lib.WordArray.random(nPaddingBytes - 1)).
	             concat(CryptoJS.lib.WordArray.create([nPaddingBytes << 24], 1));
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	return CryptoJS.pad.Iso10126;

}));

/***/ }),

/***/ 1077:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * ISO/IEC 9797-1 Padding Method 2.
	 */
	CryptoJS.pad.Iso97971 = {
	    pad: function (data, blockSize) {
	        // Add 0x80 byte
	        data.concat(CryptoJS.lib.WordArray.create([0x80000000], 1));

	        // Zero pad the rest
	        CryptoJS.pad.ZeroPadding.pad(data, blockSize);
	    },

	    unpad: function (data) {
	        // Remove zero padding
	        CryptoJS.pad.ZeroPadding.unpad(data);

	        // Remove one more byte -- the 0x80 byte
	        data.sigBytes--;
	    }
	};


	return CryptoJS.pad.Iso97971;

}));

/***/ }),

/***/ 6991:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * A noop padding strategy.
	 */
	CryptoJS.pad.NoPadding = {
	    pad: function () {
	    },

	    unpad: function () {
	    }
	};


	return CryptoJS.pad.NoPadding;

}));

/***/ }),

/***/ 6475:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Zero padding strategy.
	 */
	CryptoJS.pad.ZeroPadding = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Pad
	        data.clamp();
	        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
	    },

	    unpad: function (data) {
	        // Shortcut
	        var dataWords = data.words;

	        // Unpad
	        var i = data.sigBytes - 1;
	        for (var i = data.sigBytes - 1; i >= 0; i--) {
	            if (((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
	                data.sigBytes = i + 1;
	                break;
	            }
	        }
	    }
	};


	return CryptoJS.pad.ZeroPadding;

}));

/***/ }),

/***/ 2112:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(2153), __webpack_require__(9824));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA256 = C_algo.SHA256;
	    var HMAC = C_algo.HMAC;

	    /**
	     * Password-Based Key Derivation Function 2 algorithm.
	     */
	    var PBKDF2 = C_algo.PBKDF2 = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hasher to use. Default: SHA256
	         * @property {number} iterations The number of iterations to perform. Default: 250000
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: SHA256,
	            iterations: 250000
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.PBKDF2.create();
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Computes the Password-Based Key Derivation Function 2.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init HMAC
	            var hmac = HMAC.create(cfg.hasher, password);

	            // Initial values
	            var derivedKey = WordArray.create();
	            var blockIndex = WordArray.create([0x00000001]);

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var blockIndexWords = blockIndex.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                var block = hmac.update(salt).finalize(blockIndex);
	                hmac.reset();

	                // Shortcuts
	                var blockWords = block.words;
	                var blockWordsLength = blockWords.length;

	                // Iterations
	                var intermediate = block;
	                for (var i = 1; i < iterations; i++) {
	                    intermediate = hmac.finalize(intermediate);
	                    hmac.reset();

	                    // Shortcut
	                    var intermediateWords = intermediate.words;

	                    // XOR intermediate with block
	                    for (var j = 0; j < blockWordsLength; j++) {
	                        blockWords[j] ^= intermediateWords[j];
	                    }
	                }

	                derivedKey.concat(block);
	                blockIndexWords[0]++;
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Computes the Password-Based Key Derivation Function 2.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.PBKDF2(password, salt);
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.PBKDF2 = function (password, salt, cfg) {
	        return PBKDF2.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.PBKDF2;

}));

/***/ }),

/***/ 3974:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(8269), __webpack_require__(8214), __webpack_require__(888), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm.
	     *
	     * This is a legacy version that neglected to convert the key to little-endian.
	     * This error doesn't affect the cipher's security,
	     * but it does affect its compatibility with other implementations.
	     */
	    var RabbitLegacy = C_algo.RabbitLegacy = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
	     */
	    C.RabbitLegacy = StreamCipher._createHelper(RabbitLegacy);
	}());


	return CryptoJS.RabbitLegacy;

}));

/***/ }),

/***/ 4454:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(8269), __webpack_require__(8214), __webpack_require__(888), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm
	     */
	    var Rabbit = C_algo.Rabbit = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                K[i] = (((K[i] << 8)  | (K[i] >>> 24)) & 0x00ff00ff) |
	                       (((K[i] << 24) | (K[i] >>> 8))  & 0xff00ff00);
	            }

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
	     */
	    C.Rabbit = StreamCipher._createHelper(Rabbit);
	}());


	return CryptoJS.Rabbit;

}));

/***/ }),

/***/ 1857:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(8269), __webpack_require__(8214), __webpack_require__(888), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    /**
	     * RC4 stream cipher algorithm.
	     */
	    var RC4 = C_algo.RC4 = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;
	            var keySigBytes = key.sigBytes;

	            // Init sbox
	            var S = this._S = [];
	            for (var i = 0; i < 256; i++) {
	                S[i] = i;
	            }

	            // Key setup
	            for (var i = 0, j = 0; i < 256; i++) {
	                var keyByteIndex = i % keySigBytes;
	                var keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

	                j = (j + S[i] + keyByte) % 256;

	                // Swap
	                var t = S[i];
	                S[i] = S[j];
	                S[j] = t;
	            }

	            // Counters
	            this._i = this._j = 0;
	        },

	        _doProcessBlock: function (M, offset) {
	            M[offset] ^= generateKeystreamWord.call(this);
	        },

	        keySize: 256/32,

	        ivSize: 0
	    });

	    function generateKeystreamWord() {
	        // Shortcuts
	        var S = this._S;
	        var i = this._i;
	        var j = this._j;

	        // Generate keystream word
	        var keystreamWord = 0;
	        for (var n = 0; n < 4; n++) {
	            i = (i + 1) % 256;
	            j = (j + S[i]) % 256;

	            // Swap
	            var t = S[i];
	            S[i] = S[j];
	            S[j] = t;

	            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
	        }

	        // Update counters
	        this._i = i;
	        this._j = j;

	        return keystreamWord;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4 = StreamCipher._createHelper(RC4);

	    /**
	     * Modified RC4 stream cipher algorithm.
	     */
	    var RC4Drop = C_algo.RC4Drop = RC4.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} drop The number of keystream words to drop. Default 192
	         */
	        cfg: RC4.cfg.extend({
	            drop: 192
	        }),

	        _doReset: function () {
	            RC4._doReset.call(this);

	            // Drop
	            for (var i = this.cfg.drop; i > 0; i--) {
	                generateKeystreamWord.call(this);
	            }
	        }
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4Drop = StreamCipher._createHelper(RC4Drop);
	}());


	return CryptoJS.RC4;

}));

/***/ }),

/***/ 706:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	/** @preserve
	(c) 2012 by Cédric Mesnil. All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	*/

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var _zl = WordArray.create([
	        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13]);
	    var _zr = WordArray.create([
	        5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	        6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	        8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]);
	    var _sl = WordArray.create([
	         11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	        7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	          11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	        9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ]);
	    var _sr = WordArray.create([
	        8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	        9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	        9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	        8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]);

	    var _hl =  WordArray.create([ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
	    var _hr =  WordArray.create([ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

	    /**
	     * RIPEMD160 hash algorithm.
	     */
	    var RIPEMD160 = C_algo.RIPEMD160 = Hasher.extend({
	        _doReset: function () {
	            this._hash  = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
	        },

	        _doProcessBlock: function (M, offset) {

	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                // Swap
	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }
	            // Shortcut
	            var H  = this._hash.words;
	            var hl = _hl.words;
	            var hr = _hr.words;
	            var zl = _zl.words;
	            var zr = _zr.words;
	            var sl = _sl.words;
	            var sr = _sr.words;

	            // Working variables
	            var al, bl, cl, dl, el;
	            var ar, br, cr, dr, er;

	            ar = al = H[0];
	            br = bl = H[1];
	            cr = cl = H[2];
	            dr = dl = H[3];
	            er = el = H[4];
	            // Computation
	            var t;
	            for (var i = 0; i < 80; i += 1) {
	                t = (al +  M[offset+zl[i]])|0;
	                if (i<16){
		            t +=  f1(bl,cl,dl) + hl[0];
	                } else if (i<32) {
		            t +=  f2(bl,cl,dl) + hl[1];
	                } else if (i<48) {
		            t +=  f3(bl,cl,dl) + hl[2];
	                } else if (i<64) {
		            t +=  f4(bl,cl,dl) + hl[3];
	                } else {// if (i<80) {
		            t +=  f5(bl,cl,dl) + hl[4];
	                }
	                t = t|0;
	                t =  rotl(t,sl[i]);
	                t = (t+el)|0;
	                al = el;
	                el = dl;
	                dl = rotl(cl, 10);
	                cl = bl;
	                bl = t;

	                t = (ar + M[offset+zr[i]])|0;
	                if (i<16){
		            t +=  f5(br,cr,dr) + hr[0];
	                } else if (i<32) {
		            t +=  f4(br,cr,dr) + hr[1];
	                } else if (i<48) {
		            t +=  f3(br,cr,dr) + hr[2];
	                } else if (i<64) {
		            t +=  f2(br,cr,dr) + hr[3];
	                } else {// if (i<80) {
		            t +=  f1(br,cr,dr) + hr[4];
	                }
	                t = t|0;
	                t =  rotl(t,sr[i]) ;
	                t = (t+er)|0;
	                ar = er;
	                er = dr;
	                dr = rotl(cr, 10);
	                cr = br;
	                br = t;
	            }
	            // Intermediate hash value
	            t    = (H[1] + cl + dr)|0;
	            H[1] = (H[2] + dl + er)|0;
	            H[2] = (H[3] + el + ar)|0;
	            H[3] = (H[4] + al + br)|0;
	            H[4] = (H[0] + bl + cr)|0;
	            H[0] =  t;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
	            );
	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 5; i++) {
	                // Shortcut
	                var H_i = H[i];

	                // Swap
	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });


	    function f1(x, y, z) {
	        return ((x) ^ (y) ^ (z));

	    }

	    function f2(x, y, z) {
	        return (((x)&(y)) | ((~x)&(z)));
	    }

	    function f3(x, y, z) {
	        return (((x) | (~(y))) ^ (z));
	    }

	    function f4(x, y, z) {
	        return (((x) & (z)) | ((y)&(~(z))));
	    }

	    function f5(x, y, z) {
	        return ((x) ^ ((y) |(~(z))));

	    }

	    function rotl(x,n) {
	        return (x<<n) | (x>>>(32-n));
	    }


	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.RIPEMD160('message');
	     *     var hash = CryptoJS.RIPEMD160(wordArray);
	     */
	    C.RIPEMD160 = Hasher._createHelper(RIPEMD160);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
	     */
	    C.HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160);
	}(Math));


	return CryptoJS.RIPEMD160;

}));

/***/ }),

/***/ 2783:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-1 hash algorithm.
	     */
	    var SHA1 = C_algo.SHA1 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476,
	                0xc3d2e1f0
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];

	            // Computation
	            for (var i = 0; i < 80; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
	                    W[i] = (n << 1) | (n >>> 31);
	                }

	                var t = ((a << 5) | (a >>> 27)) + e + W[i];
	                if (i < 20) {
	                    t += ((b & c) | (~b & d)) + 0x5a827999;
	                } else if (i < 40) {
	                    t += (b ^ c ^ d) + 0x6ed9eba1;
	                } else if (i < 60) {
	                    t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
	                } else /* if (i < 80) */ {
	                    t += (b ^ c ^ d) - 0x359d3e2a;
	                }

	                e = d;
	                d = c;
	                c = (b << 30) | (b >>> 2);
	                b = a;
	                a = t;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA1('message');
	     *     var hash = CryptoJS.SHA1(wordArray);
	     */
	    C.SHA1 = Hasher._createHelper(SHA1);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA1(message, key);
	     */
	    C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
	}());


	return CryptoJS.SHA1;

}));

/***/ }),

/***/ 7792:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(2153));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA256 = C_algo.SHA256;

	    /**
	     * SHA-224 hash algorithm.
	     */
	    var SHA224 = C_algo.SHA224 = SHA256.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA256._doFinalize.call(this);

	            hash.sigBytes -= 4;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA224('message');
	     *     var hash = CryptoJS.SHA224(wordArray);
	     */
	    C.SHA224 = SHA256._createHelper(SHA224);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA224(message, key);
	     */
	    C.HmacSHA224 = SHA256._createHmacHelper(SHA224);
	}());


	return CryptoJS.SHA224;

}));

/***/ }),

/***/ 2153:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Initialization and round constants tables
	    var H = [];
	    var K = [];

	    // Compute constants
	    (function () {
	        function isPrime(n) {
	            var sqrtN = Math.sqrt(n);
	            for (var factor = 2; factor <= sqrtN; factor++) {
	                if (!(n % factor)) {
	                    return false;
	                }
	            }

	            return true;
	        }

	        function getFractionalBits(n) {
	            return ((n - (n | 0)) * 0x100000000) | 0;
	        }

	        var n = 2;
	        var nPrime = 0;
	        while (nPrime < 64) {
	            if (isPrime(n)) {
	                if (nPrime < 8) {
	                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
	                }
	                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

	                nPrime++;
	            }

	            n++;
	        }
	    }());

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-256 hash algorithm.
	     */
	    var SHA256 = C_algo.SHA256 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init(H.slice(0));
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];
	            var f = H[5];
	            var g = H[6];
	            var h = H[7];

	            // Computation
	            for (var i = 0; i < 64; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var gamma0x = W[i - 15];
	                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
	                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
	                                   (gamma0x >>> 3);

	                    var gamma1x = W[i - 2];
	                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
	                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
	                                   (gamma1x >>> 10);

	                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
	                }

	                var ch  = (e & f) ^ (~e & g);
	                var maj = (a & b) ^ (a & c) ^ (b & c);

	                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
	                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

	                var t1 = h + sigma1 + ch + K[i] + W[i];
	                var t2 = sigma0 + maj;

	                h = g;
	                g = f;
	                f = e;
	                e = (d + t1) | 0;
	                d = c;
	                c = b;
	                b = a;
	                a = (t1 + t2) | 0;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	            H[5] = (H[5] + f) | 0;
	            H[6] = (H[6] + g) | 0;
	            H[7] = (H[7] + h) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA256('message');
	     *     var hash = CryptoJS.SHA256(wordArray);
	     */
	    C.SHA256 = Hasher._createHelper(SHA256);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA256(message, key);
	     */
	    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
	}(Math));


	return CryptoJS.SHA256;

}));

/***/ }),

/***/ 3327:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(4938));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var C_algo = C.algo;

	    // Constants tables
	    var RHO_OFFSETS = [];
	    var PI_INDEXES  = [];
	    var ROUND_CONSTANTS = [];

	    // Compute Constants
	    (function () {
	        // Compute rho offset constants
	        var x = 1, y = 0;
	        for (var t = 0; t < 24; t++) {
	            RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;

	            var newX = y % 5;
	            var newY = (2 * x + 3 * y) % 5;
	            x = newX;
	            y = newY;
	        }

	        // Compute pi index constants
	        for (var x = 0; x < 5; x++) {
	            for (var y = 0; y < 5; y++) {
	                PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
	            }
	        }

	        // Compute round constants
	        var LFSR = 0x01;
	        for (var i = 0; i < 24; i++) {
	            var roundConstantMsw = 0;
	            var roundConstantLsw = 0;

	            for (var j = 0; j < 7; j++) {
	                if (LFSR & 0x01) {
	                    var bitPosition = (1 << j) - 1;
	                    if (bitPosition < 32) {
	                        roundConstantLsw ^= 1 << bitPosition;
	                    } else /* if (bitPosition >= 32) */ {
	                        roundConstantMsw ^= 1 << (bitPosition - 32);
	                    }
	                }

	                // Compute next LFSR
	                if (LFSR & 0x80) {
	                    // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
	                    LFSR = (LFSR << 1) ^ 0x71;
	                } else {
	                    LFSR <<= 1;
	                }
	            }

	            ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
	        }
	    }());

	    // Reusable objects for temporary values
	    var T = [];
	    (function () {
	        for (var i = 0; i < 25; i++) {
	            T[i] = X64Word.create();
	        }
	    }());

	    /**
	     * SHA-3 hash algorithm.
	     */
	    var SHA3 = C_algo.SHA3 = Hasher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} outputLength
	         *   The desired number of bits in the output hash.
	         *   Only values permitted are: 224, 256, 384, 512.
	         *   Default: 512
	         */
	        cfg: Hasher.cfg.extend({
	            outputLength: 512
	        }),

	        _doReset: function () {
	            var state = this._state = []
	            for (var i = 0; i < 25; i++) {
	                state[i] = new X64Word.init();
	            }

	            this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var state = this._state;
	            var nBlockSizeLanes = this.blockSize / 2;

	            // Absorb
	            for (var i = 0; i < nBlockSizeLanes; i++) {
	                // Shortcuts
	                var M2i  = M[offset + 2 * i];
	                var M2i1 = M[offset + 2 * i + 1];

	                // Swap endian
	                M2i = (
	                    (((M2i << 8)  | (M2i >>> 24)) & 0x00ff00ff) |
	                    (((M2i << 24) | (M2i >>> 8))  & 0xff00ff00)
	                );
	                M2i1 = (
	                    (((M2i1 << 8)  | (M2i1 >>> 24)) & 0x00ff00ff) |
	                    (((M2i1 << 24) | (M2i1 >>> 8))  & 0xff00ff00)
	                );

	                // Absorb message into state
	                var lane = state[i];
	                lane.high ^= M2i1;
	                lane.low  ^= M2i;
	            }

	            // Rounds
	            for (var round = 0; round < 24; round++) {
	                // Theta
	                for (var x = 0; x < 5; x++) {
	                    // Mix column lanes
	                    var tMsw = 0, tLsw = 0;
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        tMsw ^= lane.high;
	                        tLsw ^= lane.low;
	                    }

	                    // Temporary values
	                    var Tx = T[x];
	                    Tx.high = tMsw;
	                    Tx.low  = tLsw;
	                }
	                for (var x = 0; x < 5; x++) {
	                    // Shortcuts
	                    var Tx4 = T[(x + 4) % 5];
	                    var Tx1 = T[(x + 1) % 5];
	                    var Tx1Msw = Tx1.high;
	                    var Tx1Lsw = Tx1.low;

	                    // Mix surrounding columns
	                    var tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
	                    var tLsw = Tx4.low  ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        lane.high ^= tMsw;
	                        lane.low  ^= tLsw;
	                    }
	                }

	                // Rho Pi
	                for (var laneIndex = 1; laneIndex < 25; laneIndex++) {
	                    var tMsw;
	                    var tLsw;

	                    // Shortcuts
	                    var lane = state[laneIndex];
	                    var laneMsw = lane.high;
	                    var laneLsw = lane.low;
	                    var rhoOffset = RHO_OFFSETS[laneIndex];

	                    // Rotate lanes
	                    if (rhoOffset < 32) {
	                        tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
	                        tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
	                    } else /* if (rhoOffset >= 32) */ {
	                        tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
	                        tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
	                    }

	                    // Transpose lanes
	                    var TPiLane = T[PI_INDEXES[laneIndex]];
	                    TPiLane.high = tMsw;
	                    TPiLane.low  = tLsw;
	                }

	                // Rho pi at x = y = 0
	                var T0 = T[0];
	                var state0 = state[0];
	                T0.high = state0.high;
	                T0.low  = state0.low;

	                // Chi
	                for (var x = 0; x < 5; x++) {
	                    for (var y = 0; y < 5; y++) {
	                        // Shortcuts
	                        var laneIndex = x + 5 * y;
	                        var lane = state[laneIndex];
	                        var TLane = T[laneIndex];
	                        var Tx1Lane = T[((x + 1) % 5) + 5 * y];
	                        var Tx2Lane = T[((x + 2) % 5) + 5 * y];

	                        // Mix rows
	                        lane.high = TLane.high ^ (~Tx1Lane.high & Tx2Lane.high);
	                        lane.low  = TLane.low  ^ (~Tx1Lane.low  & Tx2Lane.low);
	                    }
	                }

	                // Iota
	                var lane = state[0];
	                var roundConstant = ROUND_CONSTANTS[round];
	                lane.high ^= roundConstant.high;
	                lane.low  ^= roundConstant.low;
	            }
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;
	            var blockSizeBits = this.blockSize * 32;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - nBitsLeft % 32);
	            dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var state = this._state;
	            var outputLengthBytes = this.cfg.outputLength / 8;
	            var outputLengthLanes = outputLengthBytes / 8;

	            // Squeeze
	            var hashWords = [];
	            for (var i = 0; i < outputLengthLanes; i++) {
	                // Shortcuts
	                var lane = state[i];
	                var laneMsw = lane.high;
	                var laneLsw = lane.low;

	                // Swap endian
	                laneMsw = (
	                    (((laneMsw << 8)  | (laneMsw >>> 24)) & 0x00ff00ff) |
	                    (((laneMsw << 24) | (laneMsw >>> 8))  & 0xff00ff00)
	                );
	                laneLsw = (
	                    (((laneLsw << 8)  | (laneLsw >>> 24)) & 0x00ff00ff) |
	                    (((laneLsw << 24) | (laneLsw >>> 8))  & 0xff00ff00)
	                );

	                // Squeeze state to retrieve hash
	                hashWords.push(laneLsw);
	                hashWords.push(laneMsw);
	            }

	            // Return final computed hash
	            return new WordArray.init(hashWords, outputLengthBytes);
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);

	            var state = clone._state = this._state.slice(0);
	            for (var i = 0; i < 25; i++) {
	                state[i] = state[i].clone();
	            }

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA3('message');
	     *     var hash = CryptoJS.SHA3(wordArray);
	     */
	    C.SHA3 = Hasher._createHelper(SHA3);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA3(message, key);
	     */
	    C.HmacSHA3 = Hasher._createHmacHelper(SHA3);
	}(Math));


	return CryptoJS.SHA3;

}));

/***/ }),

/***/ 7460:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(4938), __webpack_require__(34));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;
	    var SHA512 = C_algo.SHA512;

	    /**
	     * SHA-384 hash algorithm.
	     */
	    var SHA384 = C_algo.SHA384 = SHA512.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0xcbbb9d5d, 0xc1059ed8), new X64Word.init(0x629a292a, 0x367cd507),
	                new X64Word.init(0x9159015a, 0x3070dd17), new X64Word.init(0x152fecd8, 0xf70e5939),
	                new X64Word.init(0x67332667, 0xffc00b31), new X64Word.init(0x8eb44a87, 0x68581511),
	                new X64Word.init(0xdb0c2e0d, 0x64f98fa7), new X64Word.init(0x47b5481d, 0xbefa4fa4)
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA512._doFinalize.call(this);

	            hash.sigBytes -= 16;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA384('message');
	     *     var hash = CryptoJS.SHA384(wordArray);
	     */
	    C.SHA384 = SHA512._createHelper(SHA384);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA384(message, key);
	     */
	    C.HmacSHA384 = SHA512._createHmacHelper(SHA384);
	}());


	return CryptoJS.SHA384;

}));

/***/ }),

/***/ 34:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(4938));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;

	    function X64Word_create() {
	        return X64Word.create.apply(X64Word, arguments);
	    }

	    // Constants
	    var K = [
	        X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
	        X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
	        X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
	        X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
	        X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
	        X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
	        X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
	        X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
	        X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
	        X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
	        X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
	        X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
	        X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
	        X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
	        X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
	        X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
	        X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
	        X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
	        X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
	        X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
	        X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
	        X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
	        X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
	        X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
	        X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
	        X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
	        X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
	        X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
	        X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
	        X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
	        X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
	        X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
	        X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
	        X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
	        X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
	        X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
	        X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
	        X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
	        X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
	        X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
	    ];

	    // Reusable objects
	    var W = [];
	    (function () {
	        for (var i = 0; i < 80; i++) {
	            W[i] = X64Word_create();
	        }
	    }());

	    /**
	     * SHA-512 hash algorithm.
	     */
	    var SHA512 = C_algo.SHA512 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
	                new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
	                new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
	                new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var H = this._hash.words;

	            var H0 = H[0];
	            var H1 = H[1];
	            var H2 = H[2];
	            var H3 = H[3];
	            var H4 = H[4];
	            var H5 = H[5];
	            var H6 = H[6];
	            var H7 = H[7];

	            var H0h = H0.high;
	            var H0l = H0.low;
	            var H1h = H1.high;
	            var H1l = H1.low;
	            var H2h = H2.high;
	            var H2l = H2.low;
	            var H3h = H3.high;
	            var H3l = H3.low;
	            var H4h = H4.high;
	            var H4l = H4.low;
	            var H5h = H5.high;
	            var H5l = H5.low;
	            var H6h = H6.high;
	            var H6l = H6.low;
	            var H7h = H7.high;
	            var H7l = H7.low;

	            // Working variables
	            var ah = H0h;
	            var al = H0l;
	            var bh = H1h;
	            var bl = H1l;
	            var ch = H2h;
	            var cl = H2l;
	            var dh = H3h;
	            var dl = H3l;
	            var eh = H4h;
	            var el = H4l;
	            var fh = H5h;
	            var fl = H5l;
	            var gh = H6h;
	            var gl = H6l;
	            var hh = H7h;
	            var hl = H7l;

	            // Rounds
	            for (var i = 0; i < 80; i++) {
	                var Wil;
	                var Wih;

	                // Shortcut
	                var Wi = W[i];

	                // Extend message
	                if (i < 16) {
	                    Wih = Wi.high = M[offset + i * 2]     | 0;
	                    Wil = Wi.low  = M[offset + i * 2 + 1] | 0;
	                } else {
	                    // Gamma0
	                    var gamma0x  = W[i - 15];
	                    var gamma0xh = gamma0x.high;
	                    var gamma0xl = gamma0x.low;
	                    var gamma0h  = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
	                    var gamma0l  = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

	                    // Gamma1
	                    var gamma1x  = W[i - 2];
	                    var gamma1xh = gamma1x.high;
	                    var gamma1xl = gamma1x.low;
	                    var gamma1h  = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
	                    var gamma1l  = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

	                    // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
	                    var Wi7  = W[i - 7];
	                    var Wi7h = Wi7.high;
	                    var Wi7l = Wi7.low;

	                    var Wi16  = W[i - 16];
	                    var Wi16h = Wi16.high;
	                    var Wi16l = Wi16.low;

	                    Wil = gamma0l + Wi7l;
	                    Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
	                    Wil = Wil + gamma1l;
	                    Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
	                    Wil = Wil + Wi16l;
	                    Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

	                    Wi.high = Wih;
	                    Wi.low  = Wil;
	                }

	                var chh  = (eh & fh) ^ (~eh & gh);
	                var chl  = (el & fl) ^ (~el & gl);
	                var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
	                var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

	                var sigma0h = ((ah >>> 28) | (al << 4))  ^ ((ah << 30)  | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
	                var sigma0l = ((al >>> 28) | (ah << 4))  ^ ((al << 30)  | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
	                var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
	                var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

	                // t1 = h + sigma1 + ch + K[i] + W[i]
	                var Ki  = K[i];
	                var Kih = Ki.high;
	                var Kil = Ki.low;

	                var t1l = hl + sigma1l;
	                var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
	                var t1l = t1l + chl;
	                var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
	                var t1l = t1l + Kil;
	                var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
	                var t1l = t1l + Wil;
	                var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

	                // t2 = sigma0 + maj
	                var t2l = sigma0l + majl;
	                var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

	                // Update working variables
	                hh = gh;
	                hl = gl;
	                gh = fh;
	                gl = fl;
	                fh = eh;
	                fl = el;
	                el = (dl + t1l) | 0;
	                eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
	                dh = ch;
	                dl = cl;
	                ch = bh;
	                cl = bl;
	                bh = ah;
	                bl = al;
	                al = (t1l + t2l) | 0;
	                ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
	            }

	            // Intermediate hash value
	            H0l = H0.low  = (H0l + al);
	            H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
	            H1l = H1.low  = (H1l + bl);
	            H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
	            H2l = H2.low  = (H2l + cl);
	            H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
	            H3l = H3.low  = (H3l + dl);
	            H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
	            H4l = H4.low  = (H4l + el);
	            H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
	            H5l = H5.low  = (H5l + fl);
	            H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
	            H6l = H6.low  = (H6l + gl);
	            H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
	            H7l = H7.low  = (H7l + hl);
	            H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Convert hash to 32-bit word array before returning
	            var hash = this._hash.toX32();

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        },

	        blockSize: 1024/32
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA512('message');
	     *     var hash = CryptoJS.SHA512(wordArray);
	     */
	    C.SHA512 = Hasher._createHelper(SHA512);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA512(message, key);
	     */
	    C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
	}());


	return CryptoJS.SHA512;

}));

/***/ }),

/***/ 4253:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249), __webpack_require__(8269), __webpack_require__(8214), __webpack_require__(888), __webpack_require__(5109));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Permuted Choice 1 constants
	    var PC1 = [
	        57, 49, 41, 33, 25, 17, 9,  1,
	        58, 50, 42, 34, 26, 18, 10, 2,
	        59, 51, 43, 35, 27, 19, 11, 3,
	        60, 52, 44, 36, 63, 55, 47, 39,
	        31, 23, 15, 7,  62, 54, 46, 38,
	        30, 22, 14, 6,  61, 53, 45, 37,
	        29, 21, 13, 5,  28, 20, 12, 4
	    ];

	    // Permuted Choice 2 constants
	    var PC2 = [
	        14, 17, 11, 24, 1,  5,
	        3,  28, 15, 6,  21, 10,
	        23, 19, 12, 4,  26, 8,
	        16, 7,  27, 20, 13, 2,
	        41, 52, 31, 37, 47, 55,
	        30, 40, 51, 45, 33, 48,
	        44, 49, 39, 56, 34, 53,
	        46, 42, 50, 36, 29, 32
	    ];

	    // Cumulative bit shift constants
	    var BIT_SHIFTS = [1,  2,  4,  6,  8,  10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

	    // SBOXes and round permutation constants
	    var SBOX_P = [
	        {
	            0x0: 0x808200,
	            0x10000000: 0x8000,
	            0x20000000: 0x808002,
	            0x30000000: 0x2,
	            0x40000000: 0x200,
	            0x50000000: 0x808202,
	            0x60000000: 0x800202,
	            0x70000000: 0x800000,
	            0x80000000: 0x202,
	            0x90000000: 0x800200,
	            0xa0000000: 0x8200,
	            0xb0000000: 0x808000,
	            0xc0000000: 0x8002,
	            0xd0000000: 0x800002,
	            0xe0000000: 0x0,
	            0xf0000000: 0x8202,
	            0x8000000: 0x0,
	            0x18000000: 0x808202,
	            0x28000000: 0x8202,
	            0x38000000: 0x8000,
	            0x48000000: 0x808200,
	            0x58000000: 0x200,
	            0x68000000: 0x808002,
	            0x78000000: 0x2,
	            0x88000000: 0x800200,
	            0x98000000: 0x8200,
	            0xa8000000: 0x808000,
	            0xb8000000: 0x800202,
	            0xc8000000: 0x800002,
	            0xd8000000: 0x8002,
	            0xe8000000: 0x202,
	            0xf8000000: 0x800000,
	            0x1: 0x8000,
	            0x10000001: 0x2,
	            0x20000001: 0x808200,
	            0x30000001: 0x800000,
	            0x40000001: 0x808002,
	            0x50000001: 0x8200,
	            0x60000001: 0x200,
	            0x70000001: 0x800202,
	            0x80000001: 0x808202,
	            0x90000001: 0x808000,
	            0xa0000001: 0x800002,
	            0xb0000001: 0x8202,
	            0xc0000001: 0x202,
	            0xd0000001: 0x800200,
	            0xe0000001: 0x8002,
	            0xf0000001: 0x0,
	            0x8000001: 0x808202,
	            0x18000001: 0x808000,
	            0x28000001: 0x800000,
	            0x38000001: 0x200,
	            0x48000001: 0x8000,
	            0x58000001: 0x800002,
	            0x68000001: 0x2,
	            0x78000001: 0x8202,
	            0x88000001: 0x8002,
	            0x98000001: 0x800202,
	            0xa8000001: 0x202,
	            0xb8000001: 0x808200,
	            0xc8000001: 0x800200,
	            0xd8000001: 0x0,
	            0xe8000001: 0x8200,
	            0xf8000001: 0x808002
	        },
	        {
	            0x0: 0x40084010,
	            0x1000000: 0x4000,
	            0x2000000: 0x80000,
	            0x3000000: 0x40080010,
	            0x4000000: 0x40000010,
	            0x5000000: 0x40084000,
	            0x6000000: 0x40004000,
	            0x7000000: 0x10,
	            0x8000000: 0x84000,
	            0x9000000: 0x40004010,
	            0xa000000: 0x40000000,
	            0xb000000: 0x84010,
	            0xc000000: 0x80010,
	            0xd000000: 0x0,
	            0xe000000: 0x4010,
	            0xf000000: 0x40080000,
	            0x800000: 0x40004000,
	            0x1800000: 0x84010,
	            0x2800000: 0x10,
	            0x3800000: 0x40004010,
	            0x4800000: 0x40084010,
	            0x5800000: 0x40000000,
	            0x6800000: 0x80000,
	            0x7800000: 0x40080010,
	            0x8800000: 0x80010,
	            0x9800000: 0x0,
	            0xa800000: 0x4000,
	            0xb800000: 0x40080000,
	            0xc800000: 0x40000010,
	            0xd800000: 0x84000,
	            0xe800000: 0x40084000,
	            0xf800000: 0x4010,
	            0x10000000: 0x0,
	            0x11000000: 0x40080010,
	            0x12000000: 0x40004010,
	            0x13000000: 0x40084000,
	            0x14000000: 0x40080000,
	            0x15000000: 0x10,
	            0x16000000: 0x84010,
	            0x17000000: 0x4000,
	            0x18000000: 0x4010,
	            0x19000000: 0x80000,
	            0x1a000000: 0x80010,
	            0x1b000000: 0x40000010,
	            0x1c000000: 0x84000,
	            0x1d000000: 0x40004000,
	            0x1e000000: 0x40000000,
	            0x1f000000: 0x40084010,
	            0x10800000: 0x84010,
	            0x11800000: 0x80000,
	            0x12800000: 0x40080000,
	            0x13800000: 0x4000,
	            0x14800000: 0x40004000,
	            0x15800000: 0x40084010,
	            0x16800000: 0x10,
	            0x17800000: 0x40000000,
	            0x18800000: 0x40084000,
	            0x19800000: 0x40000010,
	            0x1a800000: 0x40004010,
	            0x1b800000: 0x80010,
	            0x1c800000: 0x0,
	            0x1d800000: 0x4010,
	            0x1e800000: 0x40080010,
	            0x1f800000: 0x84000
	        },
	        {
	            0x0: 0x104,
	            0x100000: 0x0,
	            0x200000: 0x4000100,
	            0x300000: 0x10104,
	            0x400000: 0x10004,
	            0x500000: 0x4000004,
	            0x600000: 0x4010104,
	            0x700000: 0x4010000,
	            0x800000: 0x4000000,
	            0x900000: 0x4010100,
	            0xa00000: 0x10100,
	            0xb00000: 0x4010004,
	            0xc00000: 0x4000104,
	            0xd00000: 0x10000,
	            0xe00000: 0x4,
	            0xf00000: 0x100,
	            0x80000: 0x4010100,
	            0x180000: 0x4010004,
	            0x280000: 0x0,
	            0x380000: 0x4000100,
	            0x480000: 0x4000004,
	            0x580000: 0x10000,
	            0x680000: 0x10004,
	            0x780000: 0x104,
	            0x880000: 0x4,
	            0x980000: 0x100,
	            0xa80000: 0x4010000,
	            0xb80000: 0x10104,
	            0xc80000: 0x10100,
	            0xd80000: 0x4000104,
	            0xe80000: 0x4010104,
	            0xf80000: 0x4000000,
	            0x1000000: 0x4010100,
	            0x1100000: 0x10004,
	            0x1200000: 0x10000,
	            0x1300000: 0x4000100,
	            0x1400000: 0x100,
	            0x1500000: 0x4010104,
	            0x1600000: 0x4000004,
	            0x1700000: 0x0,
	            0x1800000: 0x4000104,
	            0x1900000: 0x4000000,
	            0x1a00000: 0x4,
	            0x1b00000: 0x10100,
	            0x1c00000: 0x4010000,
	            0x1d00000: 0x104,
	            0x1e00000: 0x10104,
	            0x1f00000: 0x4010004,
	            0x1080000: 0x4000000,
	            0x1180000: 0x104,
	            0x1280000: 0x4010100,
	            0x1380000: 0x0,
	            0x1480000: 0x10004,
	            0x1580000: 0x4000100,
	            0x1680000: 0x100,
	            0x1780000: 0x4010004,
	            0x1880000: 0x10000,
	            0x1980000: 0x4010104,
	            0x1a80000: 0x10104,
	            0x1b80000: 0x4000004,
	            0x1c80000: 0x4000104,
	            0x1d80000: 0x4010000,
	            0x1e80000: 0x4,
	            0x1f80000: 0x10100
	        },
	        {
	            0x0: 0x80401000,
	            0x10000: 0x80001040,
	            0x20000: 0x401040,
	            0x30000: 0x80400000,
	            0x40000: 0x0,
	            0x50000: 0x401000,
	            0x60000: 0x80000040,
	            0x70000: 0x400040,
	            0x80000: 0x80000000,
	            0x90000: 0x400000,
	            0xa0000: 0x40,
	            0xb0000: 0x80001000,
	            0xc0000: 0x80400040,
	            0xd0000: 0x1040,
	            0xe0000: 0x1000,
	            0xf0000: 0x80401040,
	            0x8000: 0x80001040,
	            0x18000: 0x40,
	            0x28000: 0x80400040,
	            0x38000: 0x80001000,
	            0x48000: 0x401000,
	            0x58000: 0x80401040,
	            0x68000: 0x0,
	            0x78000: 0x80400000,
	            0x88000: 0x1000,
	            0x98000: 0x80401000,
	            0xa8000: 0x400000,
	            0xb8000: 0x1040,
	            0xc8000: 0x80000000,
	            0xd8000: 0x400040,
	            0xe8000: 0x401040,
	            0xf8000: 0x80000040,
	            0x100000: 0x400040,
	            0x110000: 0x401000,
	            0x120000: 0x80000040,
	            0x130000: 0x0,
	            0x140000: 0x1040,
	            0x150000: 0x80400040,
	            0x160000: 0x80401000,
	            0x170000: 0x80001040,
	            0x180000: 0x80401040,
	            0x190000: 0x80000000,
	            0x1a0000: 0x80400000,
	            0x1b0000: 0x401040,
	            0x1c0000: 0x80001000,
	            0x1d0000: 0x400000,
	            0x1e0000: 0x40,
	            0x1f0000: 0x1000,
	            0x108000: 0x80400000,
	            0x118000: 0x80401040,
	            0x128000: 0x0,
	            0x138000: 0x401000,
	            0x148000: 0x400040,
	            0x158000: 0x80000000,
	            0x168000: 0x80001040,
	            0x178000: 0x40,
	            0x188000: 0x80000040,
	            0x198000: 0x1000,
	            0x1a8000: 0x80001000,
	            0x1b8000: 0x80400040,
	            0x1c8000: 0x1040,
	            0x1d8000: 0x80401000,
	            0x1e8000: 0x400000,
	            0x1f8000: 0x401040
	        },
	        {
	            0x0: 0x80,
	            0x1000: 0x1040000,
	            0x2000: 0x40000,
	            0x3000: 0x20000000,
	            0x4000: 0x20040080,
	            0x5000: 0x1000080,
	            0x6000: 0x21000080,
	            0x7000: 0x40080,
	            0x8000: 0x1000000,
	            0x9000: 0x20040000,
	            0xa000: 0x20000080,
	            0xb000: 0x21040080,
	            0xc000: 0x21040000,
	            0xd000: 0x0,
	            0xe000: 0x1040080,
	            0xf000: 0x21000000,
	            0x800: 0x1040080,
	            0x1800: 0x21000080,
	            0x2800: 0x80,
	            0x3800: 0x1040000,
	            0x4800: 0x40000,
	            0x5800: 0x20040080,
	            0x6800: 0x21040000,
	            0x7800: 0x20000000,
	            0x8800: 0x20040000,
	            0x9800: 0x0,
	            0xa800: 0x21040080,
	            0xb800: 0x1000080,
	            0xc800: 0x20000080,
	            0xd800: 0x21000000,
	            0xe800: 0x1000000,
	            0xf800: 0x40080,
	            0x10000: 0x40000,
	            0x11000: 0x80,
	            0x12000: 0x20000000,
	            0x13000: 0x21000080,
	            0x14000: 0x1000080,
	            0x15000: 0x21040000,
	            0x16000: 0x20040080,
	            0x17000: 0x1000000,
	            0x18000: 0x21040080,
	            0x19000: 0x21000000,
	            0x1a000: 0x1040000,
	            0x1b000: 0x20040000,
	            0x1c000: 0x40080,
	            0x1d000: 0x20000080,
	            0x1e000: 0x0,
	            0x1f000: 0x1040080,
	            0x10800: 0x21000080,
	            0x11800: 0x1000000,
	            0x12800: 0x1040000,
	            0x13800: 0x20040080,
	            0x14800: 0x20000000,
	            0x15800: 0x1040080,
	            0x16800: 0x80,
	            0x17800: 0x21040000,
	            0x18800: 0x40080,
	            0x19800: 0x21040080,
	            0x1a800: 0x0,
	            0x1b800: 0x21000000,
	            0x1c800: 0x1000080,
	            0x1d800: 0x40000,
	            0x1e800: 0x20040000,
	            0x1f800: 0x20000080
	        },
	        {
	            0x0: 0x10000008,
	            0x100: 0x2000,
	            0x200: 0x10200000,
	            0x300: 0x10202008,
	            0x400: 0x10002000,
	            0x500: 0x200000,
	            0x600: 0x200008,
	            0x700: 0x10000000,
	            0x800: 0x0,
	            0x900: 0x10002008,
	            0xa00: 0x202000,
	            0xb00: 0x8,
	            0xc00: 0x10200008,
	            0xd00: 0x202008,
	            0xe00: 0x2008,
	            0xf00: 0x10202000,
	            0x80: 0x10200000,
	            0x180: 0x10202008,
	            0x280: 0x8,
	            0x380: 0x200000,
	            0x480: 0x202008,
	            0x580: 0x10000008,
	            0x680: 0x10002000,
	            0x780: 0x2008,
	            0x880: 0x200008,
	            0x980: 0x2000,
	            0xa80: 0x10002008,
	            0xb80: 0x10200008,
	            0xc80: 0x0,
	            0xd80: 0x10202000,
	            0xe80: 0x202000,
	            0xf80: 0x10000000,
	            0x1000: 0x10002000,
	            0x1100: 0x10200008,
	            0x1200: 0x10202008,
	            0x1300: 0x2008,
	            0x1400: 0x200000,
	            0x1500: 0x10000000,
	            0x1600: 0x10000008,
	            0x1700: 0x202000,
	            0x1800: 0x202008,
	            0x1900: 0x0,
	            0x1a00: 0x8,
	            0x1b00: 0x10200000,
	            0x1c00: 0x2000,
	            0x1d00: 0x10002008,
	            0x1e00: 0x10202000,
	            0x1f00: 0x200008,
	            0x1080: 0x8,
	            0x1180: 0x202000,
	            0x1280: 0x200000,
	            0x1380: 0x10000008,
	            0x1480: 0x10002000,
	            0x1580: 0x2008,
	            0x1680: 0x10202008,
	            0x1780: 0x10200000,
	            0x1880: 0x10202000,
	            0x1980: 0x10200008,
	            0x1a80: 0x2000,
	            0x1b80: 0x202008,
	            0x1c80: 0x200008,
	            0x1d80: 0x0,
	            0x1e80: 0x10000000,
	            0x1f80: 0x10002008
	        },
	        {
	            0x0: 0x100000,
	            0x10: 0x2000401,
	            0x20: 0x400,
	            0x30: 0x100401,
	            0x40: 0x2100401,
	            0x50: 0x0,
	            0x60: 0x1,
	            0x70: 0x2100001,
	            0x80: 0x2000400,
	            0x90: 0x100001,
	            0xa0: 0x2000001,
	            0xb0: 0x2100400,
	            0xc0: 0x2100000,
	            0xd0: 0x401,
	            0xe0: 0x100400,
	            0xf0: 0x2000000,
	            0x8: 0x2100001,
	            0x18: 0x0,
	            0x28: 0x2000401,
	            0x38: 0x2100400,
	            0x48: 0x100000,
	            0x58: 0x2000001,
	            0x68: 0x2000000,
	            0x78: 0x401,
	            0x88: 0x100401,
	            0x98: 0x2000400,
	            0xa8: 0x2100000,
	            0xb8: 0x100001,
	            0xc8: 0x400,
	            0xd8: 0x2100401,
	            0xe8: 0x1,
	            0xf8: 0x100400,
	            0x100: 0x2000000,
	            0x110: 0x100000,
	            0x120: 0x2000401,
	            0x130: 0x2100001,
	            0x140: 0x100001,
	            0x150: 0x2000400,
	            0x160: 0x2100400,
	            0x170: 0x100401,
	            0x180: 0x401,
	            0x190: 0x2100401,
	            0x1a0: 0x100400,
	            0x1b0: 0x1,
	            0x1c0: 0x0,
	            0x1d0: 0x2100000,
	            0x1e0: 0x2000001,
	            0x1f0: 0x400,
	            0x108: 0x100400,
	            0x118: 0x2000401,
	            0x128: 0x2100001,
	            0x138: 0x1,
	            0x148: 0x2000000,
	            0x158: 0x100000,
	            0x168: 0x401,
	            0x178: 0x2100400,
	            0x188: 0x2000001,
	            0x198: 0x2100000,
	            0x1a8: 0x0,
	            0x1b8: 0x2100401,
	            0x1c8: 0x100401,
	            0x1d8: 0x400,
	            0x1e8: 0x2000400,
	            0x1f8: 0x100001
	        },
	        {
	            0x0: 0x8000820,
	            0x1: 0x20000,
	            0x2: 0x8000000,
	            0x3: 0x20,
	            0x4: 0x20020,
	            0x5: 0x8020820,
	            0x6: 0x8020800,
	            0x7: 0x800,
	            0x8: 0x8020000,
	            0x9: 0x8000800,
	            0xa: 0x20800,
	            0xb: 0x8020020,
	            0xc: 0x820,
	            0xd: 0x0,
	            0xe: 0x8000020,
	            0xf: 0x20820,
	            0x80000000: 0x800,
	            0x80000001: 0x8020820,
	            0x80000002: 0x8000820,
	            0x80000003: 0x8000000,
	            0x80000004: 0x8020000,
	            0x80000005: 0x20800,
	            0x80000006: 0x20820,
	            0x80000007: 0x20,
	            0x80000008: 0x8000020,
	            0x80000009: 0x820,
	            0x8000000a: 0x20020,
	            0x8000000b: 0x8020800,
	            0x8000000c: 0x0,
	            0x8000000d: 0x8020020,
	            0x8000000e: 0x8000800,
	            0x8000000f: 0x20000,
	            0x10: 0x20820,
	            0x11: 0x8020800,
	            0x12: 0x20,
	            0x13: 0x800,
	            0x14: 0x8000800,
	            0x15: 0x8000020,
	            0x16: 0x8020020,
	            0x17: 0x20000,
	            0x18: 0x0,
	            0x19: 0x20020,
	            0x1a: 0x8020000,
	            0x1b: 0x8000820,
	            0x1c: 0x8020820,
	            0x1d: 0x20800,
	            0x1e: 0x820,
	            0x1f: 0x8000000,
	            0x80000010: 0x20000,
	            0x80000011: 0x800,
	            0x80000012: 0x8020020,
	            0x80000013: 0x20820,
	            0x80000014: 0x20,
	            0x80000015: 0x8020000,
	            0x80000016: 0x8000000,
	            0x80000017: 0x8000820,
	            0x80000018: 0x8020820,
	            0x80000019: 0x8000020,
	            0x8000001a: 0x8000800,
	            0x8000001b: 0x0,
	            0x8000001c: 0x20800,
	            0x8000001d: 0x820,
	            0x8000001e: 0x20020,
	            0x8000001f: 0x8020800
	        }
	    ];

	    // Masks that select the SBOX input
	    var SBOX_MASK = [
	        0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
	        0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f
	    ];

	    /**
	     * DES block cipher algorithm.
	     */
	    var DES = C_algo.DES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;

	            // Select 56 bits according to PC1
	            var keyBits = [];
	            for (var i = 0; i < 56; i++) {
	                var keyBitPos = PC1[i] - 1;
	                keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - keyBitPos % 32)) & 1;
	            }

	            // Assemble 16 subkeys
	            var subKeys = this._subKeys = [];
	            for (var nSubKey = 0; nSubKey < 16; nSubKey++) {
	                // Create subkey
	                var subKey = subKeys[nSubKey] = [];

	                // Shortcut
	                var bitShift = BIT_SHIFTS[nSubKey];

	                // Select 48 bits according to PC2
	                for (var i = 0; i < 24; i++) {
	                    // Select from the left 28 key bits
	                    subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - i % 6);

	                    // Select from the right 28 key bits
	                    subKey[4 + ((i / 6) | 0)] |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)] << (31 - i % 6);
	                }

	                // Since each subkey is applied to an expanded 32-bit input,
	                // the subkey can be broken into 8 values scaled to 32-bits,
	                // which allows the key to be used without expansion
	                subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
	                for (var i = 1; i < 7; i++) {
	                    subKey[i] = subKey[i] >>> ((i - 1) * 4 + 3);
	                }
	                subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
	            }

	            // Compute inverse subkeys
	            var invSubKeys = this._invSubKeys = [];
	            for (var i = 0; i < 16; i++) {
	                invSubKeys[i] = subKeys[15 - i];
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._subKeys);
	        },

	        decryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._invSubKeys);
	        },

	        _doCryptBlock: function (M, offset, subKeys) {
	            // Get input
	            this._lBlock = M[offset];
	            this._rBlock = M[offset + 1];

	            // Initial permutation
	            exchangeLR.call(this, 4,  0x0f0f0f0f);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeLR.call(this, 1,  0x55555555);

	            // Rounds
	            for (var round = 0; round < 16; round++) {
	                // Shortcuts
	                var subKey = subKeys[round];
	                var lBlock = this._lBlock;
	                var rBlock = this._rBlock;

	                // Feistel function
	                var f = 0;
	                for (var i = 0; i < 8; i++) {
	                    f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
	                }
	                this._lBlock = rBlock;
	                this._rBlock = lBlock ^ f;
	            }

	            // Undo swap from last round
	            var t = this._lBlock;
	            this._lBlock = this._rBlock;
	            this._rBlock = t;

	            // Final permutation
	            exchangeLR.call(this, 1,  0x55555555);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeLR.call(this, 4,  0x0f0f0f0f);

	            // Set output
	            M[offset] = this._lBlock;
	            M[offset + 1] = this._rBlock;
	        },

	        keySize: 64/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    // Swap bits across the left and right words
	    function exchangeLR(offset, mask) {
	        var t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
	        this._rBlock ^= t;
	        this._lBlock ^= t << offset;
	    }

	    function exchangeRL(offset, mask) {
	        var t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
	        this._lBlock ^= t;
	        this._rBlock ^= t << offset;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
	     */
	    C.DES = BlockCipher._createHelper(DES);

	    /**
	     * Triple-DES block cipher algorithm.
	     */
	    var TripleDES = C_algo.TripleDES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;
	            // Make sure the key length is valid (64, 128 or >= 192 bit)
	            if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
	                throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
	            }

	            // Extend the key according to the keying options defined in 3DES standard
	            var key1 = keyWords.slice(0, 2);
	            var key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
	            var key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

	            // Create DES instances
	            this._des1 = DES.createEncryptor(WordArray.create(key1));
	            this._des2 = DES.createEncryptor(WordArray.create(key2));
	            this._des3 = DES.createEncryptor(WordArray.create(key3));
	        },

	        encryptBlock: function (M, offset) {
	            this._des1.encryptBlock(M, offset);
	            this._des2.decryptBlock(M, offset);
	            this._des3.encryptBlock(M, offset);
	        },

	        decryptBlock: function (M, offset) {
	            this._des3.decryptBlock(M, offset);
	            this._des2.encryptBlock(M, offset);
	            this._des1.decryptBlock(M, offset);
	        },

	        keySize: 192/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
	     */
	    C.TripleDES = BlockCipher._createHelper(TripleDES);
	}());


	return CryptoJS.TripleDES;

}));

/***/ }),

/***/ 4938:
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(8249));
	}
	else {}
}(this, function (CryptoJS) {

	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var X32WordArray = C_lib.WordArray;

	    /**
	     * x64 namespace.
	     */
	    var C_x64 = C.x64 = {};

	    /**
	     * A 64-bit word.
	     */
	    var X64Word = C_x64.Word = Base.extend({
	        /**
	         * Initializes a newly created 64-bit word.
	         *
	         * @param {number} high The high 32 bits.
	         * @param {number} low The low 32 bits.
	         *
	         * @example
	         *
	         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
	         */
	        init: function (high, low) {
	            this.high = high;
	            this.low = low;
	        }

	        /**
	         * Bitwise NOTs this word.
	         *
	         * @return {X64Word} A new x64-Word object after negating.
	         *
	         * @example
	         *
	         *     var negated = x64Word.not();
	         */
	        // not: function () {
	            // var high = ~this.high;
	            // var low = ~this.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ANDs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to AND with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ANDing.
	         *
	         * @example
	         *
	         *     var anded = x64Word.and(anotherX64Word);
	         */
	        // and: function (word) {
	            // var high = this.high & word.high;
	            // var low = this.low & word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to OR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ORing.
	         *
	         * @example
	         *
	         *     var ored = x64Word.or(anotherX64Word);
	         */
	        // or: function (word) {
	            // var high = this.high | word.high;
	            // var low = this.low | word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise XORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to XOR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after XORing.
	         *
	         * @example
	         *
	         *     var xored = x64Word.xor(anotherX64Word);
	         */
	        // xor: function (word) {
	            // var high = this.high ^ word.high;
	            // var low = this.low ^ word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the left.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftL(25);
	         */
	        // shiftL: function (n) {
	            // if (n < 32) {
	                // var high = (this.high << n) | (this.low >>> (32 - n));
	                // var low = this.low << n;
	            // } else {
	                // var high = this.low << (n - 32);
	                // var low = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the right.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftR(7);
	         */
	        // shiftR: function (n) {
	            // if (n < 32) {
	                // var low = (this.low >>> n) | (this.high << (32 - n));
	                // var high = this.high >>> n;
	            // } else {
	                // var low = this.high >>> (n - 32);
	                // var high = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Rotates this word n bits to the left.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotL(25);
	         */
	        // rotL: function (n) {
	            // return this.shiftL(n).or(this.shiftR(64 - n));
	        // },

	        /**
	         * Rotates this word n bits to the right.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotR(7);
	         */
	        // rotR: function (n) {
	            // return this.shiftR(n).or(this.shiftL(64 - n));
	        // },

	        /**
	         * Adds this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to add with this word.
	         *
	         * @return {X64Word} A new x64-Word object after adding.
	         *
	         * @example
	         *
	         *     var added = x64Word.add(anotherX64Word);
	         */
	        // add: function (word) {
	            // var low = (this.low + word.low) | 0;
	            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
	            // var high = (this.high + word.high + carry) | 0;

	            // return X64Word.create(high, low);
	        // }
	    });

	    /**
	     * An array of 64-bit words.
	     *
	     * @property {Array} words The array of CryptoJS.x64.Word objects.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var X64WordArray = C_x64.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create();
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ]);
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ], 10);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 8;
	            }
	        },

	        /**
	         * Converts this 64-bit word array to a 32-bit word array.
	         *
	         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
	         *
	         * @example
	         *
	         *     var x32WordArray = x64WordArray.toX32();
	         */
	        toX32: function () {
	            // Shortcuts
	            var x64Words = this.words;
	            var x64WordsLength = x64Words.length;

	            // Convert
	            var x32Words = [];
	            for (var i = 0; i < x64WordsLength; i++) {
	                var x64Word = x64Words[i];
	                x32Words.push(x64Word.high);
	                x32Words.push(x64Word.low);
	            }

	            return X32WordArray.create(x32Words, this.sigBytes);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {X64WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = x64WordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);

	            // Clone "words" array
	            var words = clone.words = this.words.slice(0);

	            // Clone each X64Word object
	            var wordsLength = words.length;
	            for (var i = 0; i < wordsLength; i++) {
	                words[i] = words[i].clone();
	            }

	            return clone;
	        }
	    });
	}());


	return CryptoJS;

}));

/***/ }),

/***/ 1841:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(8081);
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3645);
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1667);
/* harmony import */ var _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2__);
// Imports



var ___CSS_LOADER_URL_IMPORT_0___ = new URL(/* asset import */ __webpack_require__(8529), __webpack_require__.b);
var ___CSS_LOADER_EXPORT___ = _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default()((_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default()));
var ___CSS_LOADER_URL_REPLACEMENT_0___ = _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default()(___CSS_LOADER_URL_IMPORT_0___);
// Module
___CSS_LOADER_EXPORT___.push([module.id, ".wisetrack-smart-banner__AEqYlWgPonspKfseFq2N{height:76px}@media(min-width: 428px){.wisetrack-smart-banner__AEqYlWgPonspKfseFq2N{height:0}}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq{position:fixed;left:0;right:0;z-index:10000000}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq.wisetrack-smart-banner__jOV7BvlxDT7ATfbLPh3j{top:0}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq.wisetrack-smart-banner__XmomYv1VVQYz0lEtn9Q2{bottom:0}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK{margin:0 auto;max-width:428px;background:#fff}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI{display:flex;align-items:center;padding:10px 8px 10px 4px}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__VFuxsD_KzqNSxQecFmao{width:32px;height:32px;border:none;background:url(" + ___CSS_LOADER_URL_REPLACEMENT_0___ + ");background-repeat:no-repeat;background-position:center center;background-size:8px 8px,auto;cursor:pointer}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__hqvH8Y5fwbegVLKnoYv_{width:56px;height:56px;overflow:hidden;background-color:#6e7492;border-radius:8px}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__hqvH8Y5fwbegVLKnoYv_ .wisetrack-smart-banner__Ll9XMTDiX4Drgeydp0Oc{display:flex;align-items:center;justify-content:center;width:100%;height:100%;color:#353a52;font-weight:bold;font-size:23px;font-family:ArialMt,Arial,sans-serif;line-height:32px;background-color:#e0e2ec}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__hqvH8Y5fwbegVLKnoYv_ .wisetrack-smart-banner__VYRfEif2Ph2_984rXQy8{width:100%}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__I8xX0C5dUcR53pY0aEys{flex:1 1 0%;min-height:0;min-width:0;margin:0 12px}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__JJLdp2l7YvnsUXudojWA{overflow:hidden;text-overflow:ellipsis}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI h4{margin:5px 0 8px;color:#353a52;font-family:Arial-BoldMT,ArialMt,Arial,sans-serif;font-size:12px;font-weight:bold;line-height:16px;white-space:nowrap}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI p{margin:8px 0 7px;color:#353a52;font-family:ArialMt,Arial,sans-serif;font-size:9px;line-height:11px;max-height:22px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}.wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq .wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK .wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI .wisetrack-smart-banner__risKVvV3T0vjKiSTR9l0{color:#6e7492;background:#f9fafc;border:1px solid #cdd0e0;border-radius:4px;border-color:#6e7492;box-shadow:inset 0px -1px 0px 0px #e0e2ec;padding:4px 6.5px;display:inline-block;vertical-align:middle;text-align:center;font-family:ArialMt,Arial,sans-serif;font-size:12px;font-weight:500;line-height:16px;cursor:pointer;text-decoration:none}", ""]);
// Exports
___CSS_LOADER_EXPORT___.locals = {
	"bannerContainer": "wisetrack-smart-banner__AEqYlWgPonspKfseFq2N",
	"banner": "wisetrack-smart-banner__NVk5vwju_4kdaKzGWJPq",
	"stickyToTop": "wisetrack-smart-banner__jOV7BvlxDT7ATfbLPh3j",
	"stickyToBottom": "wisetrack-smart-banner__XmomYv1VVQYz0lEtn9Q2",
	"bannerBody": "wisetrack-smart-banner__eXKzWnRDn4RWUiSSeVYK",
	"content": "wisetrack-smart-banner__r3JnN_RNhpzArrmKQ8jI",
	"dismiss": "wisetrack-smart-banner__VFuxsD_KzqNSxQecFmao",
	"appIcon": "wisetrack-smart-banner__hqvH8Y5fwbegVLKnoYv_",
	"placeholder": "wisetrack-smart-banner__Ll9XMTDiX4Drgeydp0Oc",
	"image": "wisetrack-smart-banner__VYRfEif2Ph2_984rXQy8",
	"textContainer": "wisetrack-smart-banner__I8xX0C5dUcR53pY0aEys",
	"bannerText": "wisetrack-smart-banner__JJLdp2l7YvnsUXudojWA",
	"action": "wisetrack-smart-banner__risKVvV3T0vjKiSTR9l0"
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (___CSS_LOADER_EXPORT___);


/***/ }),

/***/ 3645:
/***/ ((module) => {

"use strict";


/*
  MIT License http://www.opensource.org/licenses/mit-license.php
  Author Tobias Koppers @sokra
*/
module.exports = function (cssWithMappingToString) {
  var list = []; // return the list of modules as css string

  list.toString = function toString() {
    return this.map(function (item) {
      var content = "";
      var needLayer = typeof item[5] !== "undefined";

      if (item[4]) {
        content += "@supports (".concat(item[4], ") {");
      }

      if (item[2]) {
        content += "@media ".concat(item[2], " {");
      }

      if (needLayer) {
        content += "@layer".concat(item[5].length > 0 ? " ".concat(item[5]) : "", " {");
      }

      content += cssWithMappingToString(item);

      if (needLayer) {
        content += "}";
      }

      if (item[2]) {
        content += "}";
      }

      if (item[4]) {
        content += "}";
      }

      return content;
    }).join("");
  }; // import a list of modules into the list


  list.i = function i(modules, media, dedupe, supports, layer) {
    if (typeof modules === "string") {
      modules = [[null, modules, undefined]];
    }

    var alreadyImportedModules = {};

    if (dedupe) {
      for (var k = 0; k < this.length; k++) {
        var id = this[k][0];

        if (id != null) {
          alreadyImportedModules[id] = true;
        }
      }
    }

    for (var _k = 0; _k < modules.length; _k++) {
      var item = [].concat(modules[_k]);

      if (dedupe && alreadyImportedModules[item[0]]) {
        continue;
      }

      if (typeof layer !== "undefined") {
        if (typeof item[5] === "undefined") {
          item[5] = layer;
        } else {
          item[1] = "@layer".concat(item[5].length > 0 ? " ".concat(item[5]) : "", " {").concat(item[1], "}");
          item[5] = layer;
        }
      }

      if (media) {
        if (!item[2]) {
          item[2] = media;
        } else {
          item[1] = "@media ".concat(item[2], " {").concat(item[1], "}");
          item[2] = media;
        }
      }

      if (supports) {
        if (!item[4]) {
          item[4] = "".concat(supports);
        } else {
          item[1] = "@supports (".concat(item[4], ") {").concat(item[1], "}");
          item[4] = supports;
        }
      }

      list.push(item);
    }
  };

  return list;
};

/***/ }),

/***/ 1667:
/***/ ((module) => {

"use strict";


module.exports = function (url, options) {
  if (!options) {
    options = {};
  }

  if (!url) {
    return url;
  }

  url = String(url.__esModule ? url.default : url); // If url is already wrapped in quotes, remove them

  if (/^['"].*['"]$/.test(url)) {
    url = url.slice(1, -1);
  }

  if (options.hash) {
    url += options.hash;
  } // Should url be wrapped?
  // See https://drafts.csswg.org/css-values-3/#urls


  if (/["'() \t\n]|(%20)/.test(url) || options.needQuotes) {
    return "\"".concat(url.replace(/"/g, '\\"').replace(/\n/g, "\\n"), "\"");
  }

  return url;
};

/***/ }),

/***/ 8081:
/***/ ((module) => {

"use strict";


module.exports = function (i) {
  return i[1];
};

/***/ }),

/***/ 2702:
/***/ (function(module, __unused_webpack_exports, __webpack_require__) {

/*!
 * @overview es6-promise - a tiny implementation of Promises/A+.
 * @copyright Copyright (c) 2014 Yehuda Katz, Tom Dale, Stefan Penner and contributors (Conversion to ES6 API by Jake Archibald)
 * @license   Licensed under MIT license
 *            See https://raw.githubusercontent.com/stefanpenner/es6-promise/master/LICENSE
 * @version   v4.2.8+1e68dce6
 */

(function (global, factory) {
	 true ? module.exports = factory() :
	0;
}(this, (function () { 'use strict';

function objectOrFunction(x) {
  var type = typeof x;
  return x !== null && (type === 'object' || type === 'function');
}

function isFunction(x) {
  return typeof x === 'function';
}



var _isArray = void 0;
if (Array.isArray) {
  _isArray = Array.isArray;
} else {
  _isArray = function (x) {
    return Object.prototype.toString.call(x) === '[object Array]';
  };
}

var isArray = _isArray;

var len = 0;
var vertxNext = void 0;
var customSchedulerFn = void 0;

var asap = function asap(callback, arg) {
  queue[len] = callback;
  queue[len + 1] = arg;
  len += 2;
  if (len === 2) {
    // If len is 2, that means that we need to schedule an async flush.
    // If additional callbacks are queued before the queue is flushed, they
    // will be processed by this flush that we are scheduling.
    if (customSchedulerFn) {
      customSchedulerFn(flush);
    } else {
      scheduleFlush();
    }
  }
};

function setScheduler(scheduleFn) {
  customSchedulerFn = scheduleFn;
}

function setAsap(asapFn) {
  asap = asapFn;
}

var browserWindow = typeof window !== 'undefined' ? window : undefined;
var browserGlobal = browserWindow || {};
var BrowserMutationObserver = browserGlobal.MutationObserver || browserGlobal.WebKitMutationObserver;
var isNode = typeof self === 'undefined' && typeof process !== 'undefined' && {}.toString.call(process) === '[object process]';

// test for web worker but not in IE10
var isWorker = typeof Uint8ClampedArray !== 'undefined' && typeof importScripts !== 'undefined' && typeof MessageChannel !== 'undefined';

// node
function useNextTick() {
  // node version 0.10.x displays a deprecation warning when nextTick is used recursively
  // see https://github.com/cujojs/when/issues/410 for details
  return function () {
    return process.nextTick(flush);
  };
}

// vertx
function useVertxTimer() {
  if (typeof vertxNext !== 'undefined') {
    return function () {
      vertxNext(flush);
    };
  }

  return useSetTimeout();
}

function useMutationObserver() {
  var iterations = 0;
  var observer = new BrowserMutationObserver(flush);
  var node = document.createTextNode('');
  observer.observe(node, { characterData: true });

  return function () {
    node.data = iterations = ++iterations % 2;
  };
}

// web worker
function useMessageChannel() {
  var channel = new MessageChannel();
  channel.port1.onmessage = flush;
  return function () {
    return channel.port2.postMessage(0);
  };
}

function useSetTimeout() {
  // Store setTimeout reference so es6-promise will be unaffected by
  // other code modifying setTimeout (like sinon.useFakeTimers())
  var globalSetTimeout = setTimeout;
  return function () {
    return globalSetTimeout(flush, 1);
  };
}

var queue = new Array(1000);
function flush() {
  for (var i = 0; i < len; i += 2) {
    var callback = queue[i];
    var arg = queue[i + 1];

    callback(arg);

    queue[i] = undefined;
    queue[i + 1] = undefined;
  }

  len = 0;
}

function attemptVertx() {
  try {
    var vertx = Function('return this')().require('vertx');
    vertxNext = vertx.runOnLoop || vertx.runOnContext;
    return useVertxTimer();
  } catch (e) {
    return useSetTimeout();
  }
}

var scheduleFlush = void 0;
// Decide what async method to use to triggering processing of queued callbacks:
if (isNode) {
  scheduleFlush = useNextTick();
} else if (BrowserMutationObserver) {
  scheduleFlush = useMutationObserver();
} else if (isWorker) {
  scheduleFlush = useMessageChannel();
} else if (browserWindow === undefined && "function" === 'function') {
  scheduleFlush = attemptVertx();
} else {
  scheduleFlush = useSetTimeout();
}

function then(onFulfillment, onRejection) {
  var parent = this;

  var child = new this.constructor(noop);

  if (child[PROMISE_ID] === undefined) {
    makePromise(child);
  }

  var _state = parent._state;


  if (_state) {
    var callback = arguments[_state - 1];
    asap(function () {
      return invokeCallback(_state, child, callback, parent._result);
    });
  } else {
    subscribe(parent, child, onFulfillment, onRejection);
  }

  return child;
}

/**
  `Promise.resolve` returns a promise that will become resolved with the
  passed `value`. It is shorthand for the following:

  ```javascript
  let promise = new Promise(function(resolve, reject){
    resolve(1);
  });

  promise.then(function(value){
    // value === 1
  });
  ```

  Instead of writing the above, your code now simply becomes the following:

  ```javascript
  let promise = Promise.resolve(1);

  promise.then(function(value){
    // value === 1
  });
  ```

  @method resolve
  @static
  @param {Any} value value that the returned promise will be resolved with
  Useful for tooling.
  @return {Promise} a promise that will become fulfilled with the given
  `value`
*/
function resolve$1(object) {
  /*jshint validthis:true */
  var Constructor = this;

  if (object && typeof object === 'object' && object.constructor === Constructor) {
    return object;
  }

  var promise = new Constructor(noop);
  resolve(promise, object);
  return promise;
}

var PROMISE_ID = Math.random().toString(36).substring(2);

function noop() {}

var PENDING = void 0;
var FULFILLED = 1;
var REJECTED = 2;

function selfFulfillment() {
  return new TypeError("You cannot resolve a promise with itself");
}

function cannotReturnOwn() {
  return new TypeError('A promises callback cannot return that same promise.');
}

function tryThen(then$$1, value, fulfillmentHandler, rejectionHandler) {
  try {
    then$$1.call(value, fulfillmentHandler, rejectionHandler);
  } catch (e) {
    return e;
  }
}

function handleForeignThenable(promise, thenable, then$$1) {
  asap(function (promise) {
    var sealed = false;
    var error = tryThen(then$$1, thenable, function (value) {
      if (sealed) {
        return;
      }
      sealed = true;
      if (thenable !== value) {
        resolve(promise, value);
      } else {
        fulfill(promise, value);
      }
    }, function (reason) {
      if (sealed) {
        return;
      }
      sealed = true;

      reject(promise, reason);
    }, 'Settle: ' + (promise._label || ' unknown promise'));

    if (!sealed && error) {
      sealed = true;
      reject(promise, error);
    }
  }, promise);
}

function handleOwnThenable(promise, thenable) {
  if (thenable._state === FULFILLED) {
    fulfill(promise, thenable._result);
  } else if (thenable._state === REJECTED) {
    reject(promise, thenable._result);
  } else {
    subscribe(thenable, undefined, function (value) {
      return resolve(promise, value);
    }, function (reason) {
      return reject(promise, reason);
    });
  }
}

function handleMaybeThenable(promise, maybeThenable, then$$1) {
  if (maybeThenable.constructor === promise.constructor && then$$1 === then && maybeThenable.constructor.resolve === resolve$1) {
    handleOwnThenable(promise, maybeThenable);
  } else {
    if (then$$1 === undefined) {
      fulfill(promise, maybeThenable);
    } else if (isFunction(then$$1)) {
      handleForeignThenable(promise, maybeThenable, then$$1);
    } else {
      fulfill(promise, maybeThenable);
    }
  }
}

function resolve(promise, value) {
  if (promise === value) {
    reject(promise, selfFulfillment());
  } else if (objectOrFunction(value)) {
    var then$$1 = void 0;
    try {
      then$$1 = value.then;
    } catch (error) {
      reject(promise, error);
      return;
    }
    handleMaybeThenable(promise, value, then$$1);
  } else {
    fulfill(promise, value);
  }
}

function publishRejection(promise) {
  if (promise._onerror) {
    promise._onerror(promise._result);
  }

  publish(promise);
}

function fulfill(promise, value) {
  if (promise._state !== PENDING) {
    return;
  }

  promise._result = value;
  promise._state = FULFILLED;

  if (promise._subscribers.length !== 0) {
    asap(publish, promise);
  }
}

function reject(promise, reason) {
  if (promise._state !== PENDING) {
    return;
  }
  promise._state = REJECTED;
  promise._result = reason;

  asap(publishRejection, promise);
}

function subscribe(parent, child, onFulfillment, onRejection) {
  var _subscribers = parent._subscribers;
  var length = _subscribers.length;


  parent._onerror = null;

  _subscribers[length] = child;
  _subscribers[length + FULFILLED] = onFulfillment;
  _subscribers[length + REJECTED] = onRejection;

  if (length === 0 && parent._state) {
    asap(publish, parent);
  }
}

function publish(promise) {
  var subscribers = promise._subscribers;
  var settled = promise._state;

  if (subscribers.length === 0) {
    return;
  }

  var child = void 0,
      callback = void 0,
      detail = promise._result;

  for (var i = 0; i < subscribers.length; i += 3) {
    child = subscribers[i];
    callback = subscribers[i + settled];

    if (child) {
      invokeCallback(settled, child, callback, detail);
    } else {
      callback(detail);
    }
  }

  promise._subscribers.length = 0;
}

function invokeCallback(settled, promise, callback, detail) {
  var hasCallback = isFunction(callback),
      value = void 0,
      error = void 0,
      succeeded = true;

  if (hasCallback) {
    try {
      value = callback(detail);
    } catch (e) {
      succeeded = false;
      error = e;
    }

    if (promise === value) {
      reject(promise, cannotReturnOwn());
      return;
    }
  } else {
    value = detail;
  }

  if (promise._state !== PENDING) {
    // noop
  } else if (hasCallback && succeeded) {
    resolve(promise, value);
  } else if (succeeded === false) {
    reject(promise, error);
  } else if (settled === FULFILLED) {
    fulfill(promise, value);
  } else if (settled === REJECTED) {
    reject(promise, value);
  }
}

function initializePromise(promise, resolver) {
  try {
    resolver(function resolvePromise(value) {
      resolve(promise, value);
    }, function rejectPromise(reason) {
      reject(promise, reason);
    });
  } catch (e) {
    reject(promise, e);
  }
}

var id = 0;
function nextId() {
  return id++;
}

function makePromise(promise) {
  promise[PROMISE_ID] = id++;
  promise._state = undefined;
  promise._result = undefined;
  promise._subscribers = [];
}

function validationError() {
  return new Error('Array Methods must be provided an Array');
}

var Enumerator = function () {
  function Enumerator(Constructor, input) {
    this._instanceConstructor = Constructor;
    this.promise = new Constructor(noop);

    if (!this.promise[PROMISE_ID]) {
      makePromise(this.promise);
    }

    if (isArray(input)) {
      this.length = input.length;
      this._remaining = input.length;

      this._result = new Array(this.length);

      if (this.length === 0) {
        fulfill(this.promise, this._result);
      } else {
        this.length = this.length || 0;
        this._enumerate(input);
        if (this._remaining === 0) {
          fulfill(this.promise, this._result);
        }
      }
    } else {
      reject(this.promise, validationError());
    }
  }

  Enumerator.prototype._enumerate = function _enumerate(input) {
    for (var i = 0; this._state === PENDING && i < input.length; i++) {
      this._eachEntry(input[i], i);
    }
  };

  Enumerator.prototype._eachEntry = function _eachEntry(entry, i) {
    var c = this._instanceConstructor;
    var resolve$$1 = c.resolve;


    if (resolve$$1 === resolve$1) {
      var _then = void 0;
      var error = void 0;
      var didError = false;
      try {
        _then = entry.then;
      } catch (e) {
        didError = true;
        error = e;
      }

      if (_then === then && entry._state !== PENDING) {
        this._settledAt(entry._state, i, entry._result);
      } else if (typeof _then !== 'function') {
        this._remaining--;
        this._result[i] = entry;
      } else if (c === Promise$1) {
        var promise = new c(noop);
        if (didError) {
          reject(promise, error);
        } else {
          handleMaybeThenable(promise, entry, _then);
        }
        this._willSettleAt(promise, i);
      } else {
        this._willSettleAt(new c(function (resolve$$1) {
          return resolve$$1(entry);
        }), i);
      }
    } else {
      this._willSettleAt(resolve$$1(entry), i);
    }
  };

  Enumerator.prototype._settledAt = function _settledAt(state, i, value) {
    var promise = this.promise;


    if (promise._state === PENDING) {
      this._remaining--;

      if (state === REJECTED) {
        reject(promise, value);
      } else {
        this._result[i] = value;
      }
    }

    if (this._remaining === 0) {
      fulfill(promise, this._result);
    }
  };

  Enumerator.prototype._willSettleAt = function _willSettleAt(promise, i) {
    var enumerator = this;

    subscribe(promise, undefined, function (value) {
      return enumerator._settledAt(FULFILLED, i, value);
    }, function (reason) {
      return enumerator._settledAt(REJECTED, i, reason);
    });
  };

  return Enumerator;
}();

/**
  `Promise.all` accepts an array of promises, and returns a new promise which
  is fulfilled with an array of fulfillment values for the passed promises, or
  rejected with the reason of the first passed promise to be rejected. It casts all
  elements of the passed iterable to promises as it runs this algorithm.

  Example:

  ```javascript
  let promise1 = resolve(1);
  let promise2 = resolve(2);
  let promise3 = resolve(3);
  let promises = [ promise1, promise2, promise3 ];

  Promise.all(promises).then(function(array){
    // The array here would be [ 1, 2, 3 ];
  });
  ```

  If any of the `promises` given to `all` are rejected, the first promise
  that is rejected will be given as an argument to the returned promises's
  rejection handler. For example:

  Example:

  ```javascript
  let promise1 = resolve(1);
  let promise2 = reject(new Error("2"));
  let promise3 = reject(new Error("3"));
  let promises = [ promise1, promise2, promise3 ];

  Promise.all(promises).then(function(array){
    // Code here never runs because there are rejected promises!
  }, function(error) {
    // error.message === "2"
  });
  ```

  @method all
  @static
  @param {Array} entries array of promises
  @param {String} label optional string for labeling the promise.
  Useful for tooling.
  @return {Promise} promise that is fulfilled when all `promises` have been
  fulfilled, or rejected if any of them become rejected.
  @static
*/
function all(entries) {
  return new Enumerator(this, entries).promise;
}

/**
  `Promise.race` returns a new promise which is settled in the same way as the
  first passed promise to settle.

  Example:

  ```javascript
  let promise1 = new Promise(function(resolve, reject){
    setTimeout(function(){
      resolve('promise 1');
    }, 200);
  });

  let promise2 = new Promise(function(resolve, reject){
    setTimeout(function(){
      resolve('promise 2');
    }, 100);
  });

  Promise.race([promise1, promise2]).then(function(result){
    // result === 'promise 2' because it was resolved before promise1
    // was resolved.
  });
  ```

  `Promise.race` is deterministic in that only the state of the first
  settled promise matters. For example, even if other promises given to the
  `promises` array argument are resolved, but the first settled promise has
  become rejected before the other promises became fulfilled, the returned
  promise will become rejected:

  ```javascript
  let promise1 = new Promise(function(resolve, reject){
    setTimeout(function(){
      resolve('promise 1');
    }, 200);
  });

  let promise2 = new Promise(function(resolve, reject){
    setTimeout(function(){
      reject(new Error('promise 2'));
    }, 100);
  });

  Promise.race([promise1, promise2]).then(function(result){
    // Code here never runs
  }, function(reason){
    // reason.message === 'promise 2' because promise 2 became rejected before
    // promise 1 became fulfilled
  });
  ```

  An example real-world use case is implementing timeouts:

  ```javascript
  Promise.race([ajax('foo.json'), timeout(5000)])
  ```

  @method race
  @static
  @param {Array} promises array of promises to observe
  Useful for tooling.
  @return {Promise} a promise which settles in the same way as the first passed
  promise to settle.
*/
function race(entries) {
  /*jshint validthis:true */
  var Constructor = this;

  if (!isArray(entries)) {
    return new Constructor(function (_, reject) {
      return reject(new TypeError('You must pass an array to race.'));
    });
  } else {
    return new Constructor(function (resolve, reject) {
      var length = entries.length;
      for (var i = 0; i < length; i++) {
        Constructor.resolve(entries[i]).then(resolve, reject);
      }
    });
  }
}

/**
  `Promise.reject` returns a promise rejected with the passed `reason`.
  It is shorthand for the following:

  ```javascript
  let promise = new Promise(function(resolve, reject){
    reject(new Error('WHOOPS'));
  });

  promise.then(function(value){
    // Code here doesn't run because the promise is rejected!
  }, function(reason){
    // reason.message === 'WHOOPS'
  });
  ```

  Instead of writing the above, your code now simply becomes the following:

  ```javascript
  let promise = Promise.reject(new Error('WHOOPS'));

  promise.then(function(value){
    // Code here doesn't run because the promise is rejected!
  }, function(reason){
    // reason.message === 'WHOOPS'
  });
  ```

  @method reject
  @static
  @param {Any} reason value that the returned promise will be rejected with.
  Useful for tooling.
  @return {Promise} a promise rejected with the given `reason`.
*/
function reject$1(reason) {
  /*jshint validthis:true */
  var Constructor = this;
  var promise = new Constructor(noop);
  reject(promise, reason);
  return promise;
}

function needsResolver() {
  throw new TypeError('You must pass a resolver function as the first argument to the promise constructor');
}

function needsNew() {
  throw new TypeError("Failed to construct 'Promise': Please use the 'new' operator, this object constructor cannot be called as a function.");
}

/**
  Promise objects represent the eventual result of an asynchronous operation. The
  primary way of interacting with a promise is through its `then` method, which
  registers callbacks to receive either a promise's eventual value or the reason
  why the promise cannot be fulfilled.

  Terminology
  -----------

  - `promise` is an object or function with a `then` method whose behavior conforms to this specification.
  - `thenable` is an object or function that defines a `then` method.
  - `value` is any legal JavaScript value (including undefined, a thenable, or a promise).
  - `exception` is a value that is thrown using the throw statement.
  - `reason` is a value that indicates why a promise was rejected.
  - `settled` the final resting state of a promise, fulfilled or rejected.

  A promise can be in one of three states: pending, fulfilled, or rejected.

  Promises that are fulfilled have a fulfillment value and are in the fulfilled
  state.  Promises that are rejected have a rejection reason and are in the
  rejected state.  A fulfillment value is never a thenable.

  Promises can also be said to *resolve* a value.  If this value is also a
  promise, then the original promise's settled state will match the value's
  settled state.  So a promise that *resolves* a promise that rejects will
  itself reject, and a promise that *resolves* a promise that fulfills will
  itself fulfill.


  Basic Usage:
  ------------

  ```js
  let promise = new Promise(function(resolve, reject) {
    // on success
    resolve(value);

    // on failure
    reject(reason);
  });

  promise.then(function(value) {
    // on fulfillment
  }, function(reason) {
    // on rejection
  });
  ```

  Advanced Usage:
  ---------------

  Promises shine when abstracting away asynchronous interactions such as
  `XMLHttpRequest`s.

  ```js
  function getJSON(url) {
    return new Promise(function(resolve, reject){
      let xhr = new XMLHttpRequest();

      xhr.open('GET', url);
      xhr.onreadystatechange = handler;
      xhr.responseType = 'json';
      xhr.setRequestHeader('Accept', 'application/json');
      xhr.send();

      function handler() {
        if (this.readyState === this.DONE) {
          if (this.status === 200) {
            resolve(this.response);
          } else {
            reject(new Error('getJSON: `' + url + '` failed with status: [' + this.status + ']'));
          }
        }
      };
    });
  }

  getJSON('/posts.json').then(function(json) {
    // on fulfillment
  }, function(reason) {
    // on rejection
  });
  ```

  Unlike callbacks, promises are great composable primitives.

  ```js
  Promise.all([
    getJSON('/posts'),
    getJSON('/comments')
  ]).then(function(values){
    values[0] // => postsJSON
    values[1] // => commentsJSON

    return values;
  });
  ```

  @class Promise
  @param {Function} resolver
  Useful for tooling.
  @constructor
*/

var Promise$1 = function () {
  function Promise(resolver) {
    this[PROMISE_ID] = nextId();
    this._result = this._state = undefined;
    this._subscribers = [];

    if (noop !== resolver) {
      typeof resolver !== 'function' && needsResolver();
      this instanceof Promise ? initializePromise(this, resolver) : needsNew();
    }
  }

  /**
  The primary way of interacting with a promise is through its `then` method,
  which registers callbacks to receive either a promise's eventual value or the
  reason why the promise cannot be fulfilled.
   ```js
  findUser().then(function(user){
    // user is available
  }, function(reason){
    // user is unavailable, and you are given the reason why
  });
  ```
   Chaining
  --------
   The return value of `then` is itself a promise.  This second, 'downstream'
  promise is resolved with the return value of the first promise's fulfillment
  or rejection handler, or rejected if the handler throws an exception.
   ```js
  findUser().then(function (user) {
    return user.name;
  }, function (reason) {
    return 'default name';
  }).then(function (userName) {
    // If `findUser` fulfilled, `userName` will be the user's name, otherwise it
    // will be `'default name'`
  });
   findUser().then(function (user) {
    throw new Error('Found user, but still unhappy');
  }, function (reason) {
    throw new Error('`findUser` rejected and we're unhappy');
  }).then(function (value) {
    // never reached
  }, function (reason) {
    // if `findUser` fulfilled, `reason` will be 'Found user, but still unhappy'.
    // If `findUser` rejected, `reason` will be '`findUser` rejected and we're unhappy'.
  });
  ```
  If the downstream promise does not specify a rejection handler, rejection reasons will be propagated further downstream.
   ```js
  findUser().then(function (user) {
    throw new PedagogicalException('Upstream error');
  }).then(function (value) {
    // never reached
  }).then(function (value) {
    // never reached
  }, function (reason) {
    // The `PedgagocialException` is propagated all the way down to here
  });
  ```
   Assimilation
  ------------
   Sometimes the value you want to propagate to a downstream promise can only be
  retrieved asynchronously. This can be achieved by returning a promise in the
  fulfillment or rejection handler. The downstream promise will then be pending
  until the returned promise is settled. This is called *assimilation*.
   ```js
  findUser().then(function (user) {
    return findCommentsByAuthor(user);
  }).then(function (comments) {
    // The user's comments are now available
  });
  ```
   If the assimliated promise rejects, then the downstream promise will also reject.
   ```js
  findUser().then(function (user) {
    return findCommentsByAuthor(user);
  }).then(function (comments) {
    // If `findCommentsByAuthor` fulfills, we'll have the value here
  }, function (reason) {
    // If `findCommentsByAuthor` rejects, we'll have the reason here
  });
  ```
   Simple Example
  --------------
   Synchronous Example
   ```javascript
  let result;
   try {
    result = findResult();
    // success
  } catch(reason) {
    // failure
  }
  ```
   Errback Example
   ```js
  findResult(function(result, err){
    if (err) {
      // failure
    } else {
      // success
    }
  });
  ```
   Promise Example;
   ```javascript
  findResult().then(function(result){
    // success
  }, function(reason){
    // failure
  });
  ```
   Advanced Example
  --------------
   Synchronous Example
   ```javascript
  let author, books;
   try {
    author = findAuthor();
    books  = findBooksByAuthor(author);
    // success
  } catch(reason) {
    // failure
  }
  ```
   Errback Example
   ```js
   function foundBooks(books) {
   }
   function failure(reason) {
   }
   findAuthor(function(author, err){
    if (err) {
      failure(err);
      // failure
    } else {
      try {
        findBoooksByAuthor(author, function(books, err) {
          if (err) {
            failure(err);
          } else {
            try {
              foundBooks(books);
            } catch(reason) {
              failure(reason);
            }
          }
        });
      } catch(error) {
        failure(err);
      }
      // success
    }
  });
  ```
   Promise Example;
   ```javascript
  findAuthor().
    then(findBooksByAuthor).
    then(function(books){
      // found books
  }).catch(function(reason){
    // something went wrong
  });
  ```
   @method then
  @param {Function} onFulfilled
  @param {Function} onRejected
  Useful for tooling.
  @return {Promise}
  */

  /**
  `catch` is simply sugar for `then(undefined, onRejection)` which makes it the same
  as the catch block of a try/catch statement.
  ```js
  function findAuthor(){
  throw new Error('couldn't find that author');
  }
  // synchronous
  try {
  findAuthor();
  } catch(reason) {
  // something went wrong
  }
  // async with promises
  findAuthor().catch(function(reason){
  // something went wrong
  });
  ```
  @method catch
  @param {Function} onRejection
  Useful for tooling.
  @return {Promise}
  */


  Promise.prototype.catch = function _catch(onRejection) {
    return this.then(null, onRejection);
  };

  /**
    `finally` will be invoked regardless of the promise's fate just as native
    try/catch/finally behaves
  
    Synchronous example:
  
    ```js
    findAuthor() {
      if (Math.random() > 0.5) {
        throw new Error();
      }
      return new Author();
    }
  
    try {
      return findAuthor(); // succeed or fail
    } catch(error) {
      return findOtherAuther();
    } finally {
      // always runs
      // doesn't affect the return value
    }
    ```
  
    Asynchronous example:
  
    ```js
    findAuthor().catch(function(reason){
      return findOtherAuther();
    }).finally(function(){
      // author was either found, or not
    });
    ```
  
    @method finally
    @param {Function} callback
    @return {Promise}
  */


  Promise.prototype.finally = function _finally(callback) {
    var promise = this;
    var constructor = promise.constructor;

    if (isFunction(callback)) {
      return promise.then(function (value) {
        return constructor.resolve(callback()).then(function () {
          return value;
        });
      }, function (reason) {
        return constructor.resolve(callback()).then(function () {
          throw reason;
        });
      });
    }

    return promise.then(callback, callback);
  };

  return Promise;
}();

Promise$1.prototype.then = then;
Promise$1.all = all;
Promise$1.race = race;
Promise$1.resolve = resolve$1;
Promise$1.reject = reject$1;
Promise$1._setScheduler = setScheduler;
Promise$1._setAsap = setAsap;
Promise$1._asap = asap;

/*global self*/
function polyfill() {
  var local = void 0;

  if (typeof __webpack_require__.g !== 'undefined') {
    local = __webpack_require__.g;
  } else if (typeof self !== 'undefined') {
    local = self;
  } else {
    try {
      local = Function('return this')();
    } catch (e) {
      throw new Error('polyfill failed because global object is unavailable in this environment');
    }
  }

  var P = local.Promise;

  if (P) {
    var promiseToString = null;
    try {
      promiseToString = Object.prototype.toString.call(P.resolve());
    } catch (e) {
      // silently ignored
    }

    if (promiseToString === '[object Promise]' && !P.cast) {
      return;
    }
  }

  local.Promise = Promise$1;
}

// Strange compat..
Promise$1.polyfill = polyfill;
Promise$1.Promise = Promise$1;

return Promise$1;

})));



//# sourceMappingURL=es6-promise.map


/***/ }),

/***/ 3379:
/***/ ((module) => {

"use strict";


var stylesInDOM = [];

function getIndexByIdentifier(identifier) {
  var result = -1;

  for (var i = 0; i < stylesInDOM.length; i++) {
    if (stylesInDOM[i].identifier === identifier) {
      result = i;
      break;
    }
  }

  return result;
}

function modulesToDom(list, options) {
  var idCountMap = {};
  var identifiers = [];

  for (var i = 0; i < list.length; i++) {
    var item = list[i];
    var id = options.base ? item[0] + options.base : item[0];
    var count = idCountMap[id] || 0;
    var identifier = "".concat(id, " ").concat(count);
    idCountMap[id] = count + 1;
    var indexByIdentifier = getIndexByIdentifier(identifier);
    var obj = {
      css: item[1],
      media: item[2],
      sourceMap: item[3],
      supports: item[4],
      layer: item[5]
    };

    if (indexByIdentifier !== -1) {
      stylesInDOM[indexByIdentifier].references++;
      stylesInDOM[indexByIdentifier].updater(obj);
    } else {
      var updater = addElementStyle(obj, options);
      options.byIndex = i;
      stylesInDOM.splice(i, 0, {
        identifier: identifier,
        updater: updater,
        references: 1
      });
    }

    identifiers.push(identifier);
  }

  return identifiers;
}

function addElementStyle(obj, options) {
  var api = options.domAPI(options);
  api.update(obj);

  var updater = function updater(newObj) {
    if (newObj) {
      if (newObj.css === obj.css && newObj.media === obj.media && newObj.sourceMap === obj.sourceMap && newObj.supports === obj.supports && newObj.layer === obj.layer) {
        return;
      }

      api.update(obj = newObj);
    } else {
      api.remove();
    }
  };

  return updater;
}

module.exports = function (list, options) {
  options = options || {};
  list = list || [];
  var lastIdentifiers = modulesToDom(list, options);
  return function update(newList) {
    newList = newList || [];

    for (var i = 0; i < lastIdentifiers.length; i++) {
      var identifier = lastIdentifiers[i];
      var index = getIndexByIdentifier(identifier);
      stylesInDOM[index].references--;
    }

    var newLastIdentifiers = modulesToDom(newList, options);

    for (var _i = 0; _i < lastIdentifiers.length; _i++) {
      var _identifier = lastIdentifiers[_i];

      var _index = getIndexByIdentifier(_identifier);

      if (stylesInDOM[_index].references === 0) {
        stylesInDOM[_index].updater();

        stylesInDOM.splice(_index, 1);
      }
    }

    lastIdentifiers = newLastIdentifiers;
  };
};

/***/ }),

/***/ 569:
/***/ ((module) => {

"use strict";


var memo = {};
/* istanbul ignore next  */

function getTarget(target) {
  if (typeof memo[target] === "undefined") {
    var styleTarget = document.querySelector(target); // Special case to return head of iframe instead of iframe itself

    if (window.HTMLIFrameElement && styleTarget instanceof window.HTMLIFrameElement) {
      try {
        // This will throw an exception if access to iframe is blocked
        // due to cross-origin restrictions
        styleTarget = styleTarget.contentDocument.head;
      } catch (e) {
        // istanbul ignore next
        styleTarget = null;
      }
    }

    memo[target] = styleTarget;
  }

  return memo[target];
}
/* istanbul ignore next  */


function insertBySelector(insert, style) {
  var target = getTarget(insert);

  if (!target) {
    throw new Error("Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid.");
  }

  target.appendChild(style);
}

module.exports = insertBySelector;

/***/ }),

/***/ 9216:
/***/ ((module) => {

"use strict";


/* istanbul ignore next  */
function insertStyleElement(options) {
  var element = document.createElement("style");
  options.setAttributes(element, options.attributes);
  options.insert(element, options.options);
  return element;
}

module.exports = insertStyleElement;

/***/ }),

/***/ 3565:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


/* istanbul ignore next  */
function setAttributesWithoutAttributes(styleElement) {
  var nonce =  true ? __webpack_require__.nc : 0;

  if (nonce) {
    styleElement.setAttribute("nonce", nonce);
  }
}

module.exports = setAttributesWithoutAttributes;

/***/ }),

/***/ 7795:
/***/ ((module) => {

"use strict";


/* istanbul ignore next  */
function apply(styleElement, options, obj) {
  var css = "";

  if (obj.supports) {
    css += "@supports (".concat(obj.supports, ") {");
  }

  if (obj.media) {
    css += "@media ".concat(obj.media, " {");
  }

  var needLayer = typeof obj.layer !== "undefined";

  if (needLayer) {
    css += "@layer".concat(obj.layer.length > 0 ? " ".concat(obj.layer) : "", " {");
  }

  css += obj.css;

  if (needLayer) {
    css += "}";
  }

  if (obj.media) {
    css += "}";
  }

  if (obj.supports) {
    css += "}";
  }

  var sourceMap = obj.sourceMap;

  if (sourceMap && typeof btoa !== "undefined") {
    css += "\n/*# sourceMappingURL=data:application/json;base64,".concat(btoa(unescape(encodeURIComponent(JSON.stringify(sourceMap)))), " */");
  } // For old IE

  /* istanbul ignore if  */


  options.styleTagTransform(css, styleElement, options.options);
}

function removeStyleElement(styleElement) {
  // istanbul ignore if
  if (styleElement.parentNode === null) {
    return false;
  }

  styleElement.parentNode.removeChild(styleElement);
}
/* istanbul ignore next  */


function domAPI(options) {
  var styleElement = options.insertStyleElement(options);
  return {
    update: function update(obj) {
      apply(styleElement, options, obj);
    },
    remove: function remove() {
      removeStyleElement(styleElement);
    }
  };
}

module.exports = domAPI;

/***/ }),

/***/ 4589:
/***/ ((module) => {

"use strict";


/* istanbul ignore next  */
function styleTagTransform(css, styleElement) {
  if (styleElement.styleSheet) {
    styleElement.styleSheet.cssText = css;
  } else {
    while (styleElement.firstChild) {
      styleElement.removeChild(styleElement.firstChild);
    }

    styleElement.appendChild(document.createTextNode(css));
  }
}

module.exports = styleTagTransform;

/***/ }),

/***/ 8529:
/***/ ((module) => {

"use strict";
module.exports = "data:image/svg+xml;utf8,    <svg xmlns=%27http://www.w3.org/2000/svg%27 version=%271.1%27 preserveAspectRatio=%27none%27 viewBox=%270 0 16 16%27>      <path d=%27M1 0 L0 1 L15 16 L16 15 L1 0%27 fill=%27%236e7492%27/>      <path d=%27M16 1 L16 1 L1 16 L0 15 L15 0%27 fill=%27%236e7492%27/>    </svg>";

/***/ }),

/***/ 2480:
/***/ (() => {

/* (ignored) */

/***/ }),

/***/ 5181:
/***/ (function(module, exports, __webpack_require__) {

var __WEBPACK_AMD_DEFINE_RESULT__;/////////////////////////////////////////////////////////////////////////////////
/* UAParser.js v2.0.0
   Copyright © 2012-2024 Faisal Salman <f@faisalman.com>
   AGPLv3 License *//*
   Detect Browser, Engine, OS, CPU, and Device type/model from User-Agent data.
   Supports browser & node.js environment. 
   Demo   : https://uaparser.dev
   Source : https://github.com/faisalman/ua-parser-js */
/////////////////////////////////////////////////////////////////////////////////

/* jshint esversion: 3 */ 
/* globals window */

(function (window, undefined) {

    'use strict';
    
    //////////////
    // Constants
    /////////////

    var LIBVERSION  = '2.0.0',
        EMPTY       = '',
        UNKNOWN     = '?',
        FUNC_TYPE   = 'function',
        UNDEF_TYPE  = 'undefined',
        OBJ_TYPE    = 'object',
        STR_TYPE    = 'string',
        MAJOR       = 'major',
        MODEL       = 'model',
        NAME        = 'name',
        TYPE        = 'type',
        VENDOR      = 'vendor',
        VERSION     = 'version',
        ARCHITECTURE= 'architecture',
        CONSOLE     = 'console',
        MOBILE      = 'mobile',
        TABLET      = 'tablet',
        SMARTTV     = 'smarttv',
        WEARABLE    = 'wearable',
        XR          = 'xr',
        EMBEDDED    = 'embedded',
        INAPP       = 'inapp',
        USER_AGENT  = 'user-agent',
        UA_MAX_LENGTH = 500,
        BRANDS      = 'brands',
        FORMFACTORS = 'formFactors',
        FULLVERLIST = 'fullVersionList',
        PLATFORM    = 'platform',
        PLATFORMVER = 'platformVersion',
        BITNESS     = 'bitness',
        CH_HEADER   = 'sec-ch-ua',
        CH_HEADER_FULL_VER_LIST = CH_HEADER + '-full-version-list',
        CH_HEADER_ARCH      = CH_HEADER + '-arch',
        CH_HEADER_BITNESS   = CH_HEADER + '-' + BITNESS,
        CH_HEADER_FORM_FACTORS = CH_HEADER + '-form-factors',
        CH_HEADER_MOBILE    = CH_HEADER + '-' + MOBILE,
        CH_HEADER_MODEL     = CH_HEADER + '-' + MODEL,
        CH_HEADER_PLATFORM  = CH_HEADER + '-' + PLATFORM,
        CH_HEADER_PLATFORM_VER = CH_HEADER_PLATFORM + '-version',
        CH_ALL_VALUES       = [BRANDS, FULLVERLIST, MOBILE, MODEL, PLATFORM, PLATFORMVER, ARCHITECTURE, FORMFACTORS, BITNESS],
        UA_BROWSER  = 'browser',
        UA_CPU      = 'cpu',
        UA_DEVICE   = 'device',
        UA_ENGINE   = 'engine',
        UA_OS       = 'os',
        UA_RESULT   = 'result',
        AMAZON      = 'Amazon',
        APPLE       = 'Apple',
        ASUS        = 'ASUS',
        BLACKBERRY  = 'BlackBerry',
        GOOGLE      = 'Google',
        HUAWEI      = 'Huawei',
        LENOVO      = 'Lenovo',
        HONOR       = 'Honor',
        LG          = 'LG',
        MICROSOFT   = 'Microsoft',
        MOTOROLA    = 'Motorola',
        SAMSUNG     = 'Samsung',
        SHARP       = 'Sharp',
        SONY        = 'Sony',
        XIAOMI      = 'Xiaomi',
        ZEBRA       = 'Zebra',
        PREFIX_MOBILE  = 'Mobile ',
        SUFFIX_BROWSER = ' Browser',
        CHROME      = 'Chrome',
        CHROMECAST  = 'Chromecast',
        EDGE        = 'Edge',
        FIREFOX     = 'Firefox',
        OPERA       = 'Opera',
        FACEBOOK    = 'Facebook',
        SOGOU       = 'Sogou',
        WINDOWS     = 'Windows';
   
    var isWindow            = typeof window !== UNDEF_TYPE,
        NAVIGATOR           = (isWindow && window.navigator) ? 
                                window.navigator : 
                                undefined,
        NAVIGATOR_UADATA    = (NAVIGATOR && NAVIGATOR.userAgentData) ? 
                                NAVIGATOR.userAgentData : 
                                undefined;

    ///////////
    // Helper
    //////////

    var extend = function (defaultRgx, extensions) {
            var mergedRgx = {};
            var extraRgx = extensions;
            if (!isExtensions(extensions)) {
                extraRgx = {};
                for (var i in extensions) {
                    for (var j in extensions[i]) {
                        extraRgx[j] = extensions[i][j].concat(extraRgx[j] ? extraRgx[j] : []);
                    }
                }
            }
            for (var k in defaultRgx) {
                mergedRgx[k] = extraRgx[k] && extraRgx[k].length % 2 === 0 ? extraRgx[k].concat(defaultRgx[k]) : defaultRgx[k];
            }
            return mergedRgx;
        },
        enumerize = function (arr) {
            var enums = {};
            for (var i=0; i<arr.length; i++) {
                enums[arr[i].toUpperCase()] = arr[i];
            }
            return enums;
        },
        has = function (str1, str2) {
            if (typeof str1 === OBJ_TYPE && str1.length > 0) {
                for (var i in str1) {
                    if (lowerize(str1[i]) == lowerize(str2)) return true;
                }
                return false;
            }
            return isString(str1) ? lowerize(str2).indexOf(lowerize(str1)) !== -1 : false;
        },
        isExtensions = function (obj, deep) {
            for (var prop in obj) {
                return /^(browser|cpu|device|engine|os)$/.test(prop) || (deep ? isExtensions(obj[prop]) : false);
            }
        },
        isString = function (val) {
            return typeof val === STR_TYPE;
        },
        itemListToArray = function (header) {
            if (!header) return undefined;
            var arr = [];
            var tokens = strip(/\\?\"/g, header).split(',');
            for (var i = 0; i < tokens.length; i++) {
                if (tokens[i].indexOf(';') > -1) {
                    var token = trim(tokens[i]).split(';v=');
                    arr[i] = { brand : token[0], version : token[1] };
                } else {
                    arr[i] = trim(tokens[i]);
                }
            }
            return arr;
        },
        lowerize = function (str) {
            return isString(str) ? str.toLowerCase() : str;
        },
        majorize = function (version) {
            return isString(version) ? strip(/[^\d\.]/g, version).split('.')[0] : undefined;
        },
        setProps = function (arr) {
            for (var i in arr) {
                var propName = arr[i];
                if (typeof propName == OBJ_TYPE && propName.length == 2) {
                    this[propName[0]] = propName[1];
                } else {
                    this[propName] = undefined;
                }
            }
            return this;
        },
        strip = function (pattern, str) {
            return isString(str) ? str.replace(pattern, EMPTY) : str;
        },
        stripQuotes = function (str) {
            return strip(/\\?\"/g, str); 
        },
        trim = function (str, len) {
            if (isString(str)) {
                str = strip(/^\s\s*/, str);
                return typeof len === UNDEF_TYPE ? str : str.substring(0, UA_MAX_LENGTH);
            }
    };

    ///////////////
    // Map helper
    //////////////

    var rgxMapper = function (ua, arrays) {

            if(!ua || !arrays) return;

            var i = 0, j, k, p, q, matches, match;

            // loop through all regexes maps
            while (i < arrays.length && !matches) {

                var regex = arrays[i],       // even sequence (0,2,4,..)
                    props = arrays[i + 1];   // odd sequence (1,3,5,..)
                j = k = 0;

                // try matching uastring with regexes
                while (j < regex.length && !matches) {

                    if (!regex[j]) { break; }
                    matches = regex[j++].exec(ua);

                    if (!!matches) {
                        for (p = 0; p < props.length; p++) {
                            match = matches[++k];
                            q = props[p];
                            // check if given property is actually array
                            if (typeof q === OBJ_TYPE && q.length > 0) {
                                if (q.length === 2) {
                                    if (typeof q[1] == FUNC_TYPE) {
                                        // assign modified match
                                        this[q[0]] = q[1].call(this, match);
                                    } else {
                                        // assign given value, ignore regex match
                                        this[q[0]] = q[1];
                                    }
                                } else if (q.length === 3) {
                                    // check whether function or regex
                                    if (typeof q[1] === FUNC_TYPE && !(q[1].exec && q[1].test)) {
                                        // call function (usually string mapper)
                                        this[q[0]] = match ? q[1].call(this, match, q[2]) : undefined;
                                    } else {
                                        // sanitize match using given regex
                                        this[q[0]] = match ? match.replace(q[1], q[2]) : undefined;
                                    }
                                } else if (q.length === 4) {
                                        this[q[0]] = match ? q[3].call(this, match.replace(q[1], q[2])) : undefined;
                                }
                            } else {
                                this[q] = match ? match : undefined;
                            }
                        }
                    }
                }
                i += 2;
            }
        },

        strMapper = function (str, map) {

            for (var i in map) {
                // check if current value is array
                if (typeof map[i] === OBJ_TYPE && map[i].length > 0) {
                    for (var j = 0; j < map[i].length; j++) {
                        if (has(map[i][j], str)) {
                            return (i === UNKNOWN) ? undefined : i;
                        }
                    }
                } else if (has(map[i], str)) {
                    return (i === UNKNOWN) ? undefined : i;
                }
            }
            return map.hasOwnProperty('*') ? map['*'] : str;
    };

    ///////////////
    // String map
    //////////////

    var windowsVersionMap = {
            'ME'        : '4.90',
            'NT 3.11'   : 'NT3.51',
            'NT 4.0'    : 'NT4.0',
            '2000'      : 'NT 5.0',
            'XP'        : ['NT 5.1', 'NT 5.2'],
            'Vista'     : 'NT 6.0',
            '7'         : 'NT 6.1',
            '8'         : 'NT 6.2',
            '8.1'       : 'NT 6.3',
            '10'        : ['NT 6.4', 'NT 10.0'],
            'RT'        : 'ARM'
        },
        
        formFactorsMap = {
            'embedded'  : 'Automotive',
            'mobile'    : 'Mobile',
            'tablet'    : ['Tablet', 'EInk'],
            'smarttv'   : 'TV',
            'wearable'  : 'Watch',
            'xr'        : ['VR', 'XR'],
            '?'         : ['Desktop', 'Unknown'],
            '*'         : undefined
    };

    //////////////
    // Regex map
    /////////////

    var defaultRegexes = {

        browser : [[

            // Most common regardless engine
            /\b(?:crmo|crios)\/([\w\.]+)/i                                      // Chrome for Android/iOS
            ], [VERSION, [NAME, PREFIX_MOBILE + 'Chrome']], [
            /edg(?:e|ios|a)?\/([\w\.]+)/i                                       // Microsoft Edge
            ], [VERSION, [NAME, 'Edge']], [

            // Presto based
            /(opera mini)\/([-\w\.]+)/i,                                        // Opera Mini
            /(opera [mobiletab]{3,6})\b.+version\/([-\w\.]+)/i,                 // Opera Mobi/Tablet
            /(opera)(?:.+version\/|[\/ ]+)([\w\.]+)/i                           // Opera
            ], [NAME, VERSION], [
            /opios[\/ ]+([\w\.]+)/i                                             // Opera mini on iphone >= 8.0
            ], [VERSION, [NAME, OPERA+' Mini']], [
            /\bop(?:rg)?x\/([\w\.]+)/i                                          // Opera GX
            ], [VERSION, [NAME, OPERA+' GX']], [
            /\bopr\/([\w\.]+)/i                                                 // Opera Webkit
            ], [VERSION, [NAME, OPERA]], [

            // Mixed
            /\bb[ai]*d(?:uhd|[ub]*[aekoprswx]{5,6})[\/ ]?([\w\.]+)/i            // Baidu
            ], [VERSION, [NAME, 'Baidu']], [
            /\b(?:mxbrowser|mxios|myie2)\/?([-\w\.]*)\b/i                       // Maxthon
            ], [VERSION, [NAME, 'Maxthon']], [
            /(kindle)\/([\w\.]+)/i,                                             // Kindle
            /(lunascape|maxthon|netfront|jasmine|blazer|sleipnir)[\/ ]?([\w\.]*)/i,      
                                                                                // Lunascape/Maxthon/Netfront/Jasmine/Blazer/Sleipnir
            // Trident based
            /(avant|iemobile|slim(?:browser|boat|jet))[\/ ]?([\d\.]*)/i,        // Avant/IEMobile/SlimBrowser/SlimBoat/Slimjet
            /(?:ms|\()(ie) ([\w\.]+)/i,                                         // Internet Explorer

            // Blink/Webkit/KHTML based                                         // Flock/RockMelt/Midori/Epiphany/Silk/Skyfire/Bolt/Iron/Iridium/PhantomJS/Bowser/QupZilla/Falkon
            /(flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser|qupzilla|falkon|rekonq|puffin|brave|whale(?!.+naver)|qqbrowserlite|duckduckgo|klar|helio|(?=comodo_)?dragon)\/([-\w\.]+)/i,
                                                                                // Rekonq/Puffin/Brave/Whale/QQBrowserLite/QQ//Vivaldi/DuckDuckGo/Klar/Helio/Dragon
            /(heytap|ovi|115)browser\/([\d\.]+)/i,                              // HeyTap/Ovi/115
            /(weibo)__([\d\.]+)/i                                               // Weibo
            ], [NAME, VERSION], [
            /quark(?:pc)?\/([-\w\.]+)/i                                         // Quark
            ], [VERSION, [NAME, 'Quark']], [
            /\bddg\/([\w\.]+)/i                                                 // DuckDuckGo
            ], [VERSION, [NAME, 'DuckDuckGo']], [
            /(?:\buc? ?browser|(?:juc.+)ucweb)[\/ ]?([\w\.]+)/i                 // UCBrowser
            ], [VERSION, [NAME, 'UCBrowser']], [
            /microm.+\bqbcore\/([\w\.]+)/i,                                     // WeChat Desktop for Windows Built-in Browser
            /\bqbcore\/([\w\.]+).+microm/i,
            /micromessenger\/([\w\.]+)/i                                        // WeChat
            ], [VERSION, [NAME, 'WeChat']], [
            /konqueror\/([\w\.]+)/i                                             // Konqueror
            ], [VERSION, [NAME, 'Konqueror']], [
            /trident.+rv[: ]([\w\.]{1,9})\b.+like gecko/i                       // IE11
            ], [VERSION, [NAME, 'IE']], [
            /ya(?:search)?browser\/([\w\.]+)/i                                  // Yandex
            ], [VERSION, [NAME, 'Yandex']], [
            /slbrowser\/([\w\.]+)/i                                             // Smart Lenovo Browser
            ], [VERSION, [NAME, 'Smart ' + LENOVO + SUFFIX_BROWSER]], [
            /(avast|avg)\/([\w\.]+)/i                                           // Avast/AVG Secure Browser
            ], [[NAME, /(.+)/, '$1 Secure' + SUFFIX_BROWSER], VERSION], [
            /\bfocus\/([\w\.]+)/i                                               // Firefox Focus
            ], [VERSION, [NAME, FIREFOX+' Focus']], [
            /\bopt\/([\w\.]+)/i                                                 // Opera Touch
            ], [VERSION, [NAME, OPERA+' Touch']], [
            /coc_coc\w+\/([\w\.]+)/i                                            // Coc Coc Browser
            ], [VERSION, [NAME, 'Coc Coc']], [
            /dolfin\/([\w\.]+)/i                                                // Dolphin
            ], [VERSION, [NAME, 'Dolphin']], [
            /coast\/([\w\.]+)/i                                                 // Opera Coast
            ], [VERSION, [NAME, OPERA+' Coast']], [
            /miuibrowser\/([\w\.]+)/i                                           // MIUI Browser
            ], [VERSION, [NAME, 'MIUI' + SUFFIX_BROWSER]], [
            /fxios\/([\w\.-]+)/i                                                // Firefox for iOS
            ], [VERSION, [NAME, PREFIX_MOBILE + FIREFOX]], [
            /\bqihoobrowser\/?([\w\.]*)/i                                       // 360
            ], [VERSION, [NAME, '360']], [
            /\b(qq)\/([\w\.]+)/i                                                // QQ
            ], [[NAME, /(.+)/, '$1Browser'], VERSION], [
            /(oculus|sailfish|huawei|vivo|pico)browser\/([\w\.]+)/i
            ], [[NAME, /(.+)/, '$1' + SUFFIX_BROWSER], VERSION], [              // Oculus/Sailfish/HuaweiBrowser/VivoBrowser/PicoBrowser
            /samsungbrowser\/([\w\.]+)/i                                        // Samsung Internet
            ], [VERSION, [NAME, SAMSUNG + ' Internet']], [
            /metasr[\/ ]?([\d\.]+)/i                                            // Sogou Explorer
            ], [VERSION, [NAME, SOGOU + ' Explorer']], [
            /(sogou)mo\w+\/([\d\.]+)/i                                          // Sogou Mobile
            ], [[NAME, SOGOU + ' Mobile'], VERSION], [
            /(electron)\/([\w\.]+) safari/i,                                    // Electron-based App
            /(tesla)(?: qtcarbrowser|\/(20\d\d\.[-\w\.]+))/i,                   // Tesla
            /m?(qqbrowser|2345(?=browser|chrome|explorer))\w*[\/ ]?v?([\w\.]+)/i   // QQ/2345
            ], [NAME, VERSION], [
            /(lbbrowser|rekonq)/i                                               // LieBao Browser/Rekonq
            ], [NAME], [
            /ome\/([\w\.]+) \w* ?(iron) saf/i,                                  // Iron
            /ome\/([\w\.]+).+qihu (360)[es]e/i                                  // 360
            ], [VERSION, NAME], [

            // WebView
            /((?:fban\/fbios|fb_iab\/fb4a)(?!.+fbav)|;fbav\/([\w\.]+);)/i       // Facebook App for iOS & Android
            ], [[NAME, FACEBOOK], VERSION, [TYPE, INAPP]], [
            /(Klarna)\/([\w\.]+)/i,                                             // Klarna Shopping Browser for iOS & Android
            /(kakao(?:talk|story))[\/ ]([\w\.]+)/i,                             // Kakao App
            /(naver)\(.*?(\d+\.[\w\.]+).*\)/i,                                  // Naver InApp
            /safari (line)\/([\w\.]+)/i,                                        // Line App for iOS
            /\b(line)\/([\w\.]+)\/iab/i,                                        // Line App for Android
            /(alipay)client\/([\w\.]+)/i,                                       // Alipay
            /(twitter)(?:and| f.+e\/([\w\.]+))/i,                               // Twitter
            /(instagram|snapchat)[\/ ]([-\w\.]+)/i                              // Instagram/Snapchat
            ], [NAME, VERSION, [TYPE, INAPP]], [
            /\bgsa\/([\w\.]+) .*safari\//i                                      // Google Search Appliance on iOS
            ], [VERSION, [NAME, 'GSA'], [TYPE, INAPP]], [
            /musical_ly(?:.+app_?version\/|_)([\w\.]+)/i                        // TikTok
            ], [VERSION, [NAME, 'TikTok'], [TYPE, INAPP]], [
            /\[(linkedin)app\]/i                                                // LinkedIn App for iOS & Android
            ], [NAME, [TYPE, INAPP]], [

            /(chromium)[\/ ]([-\w\.]+)/i                                        // Chromium
            ], [NAME, VERSION], [

            /headlesschrome(?:\/([\w\.]+)| )/i                                  // Chrome Headless
            ], [VERSION, [NAME, CHROME+' Headless']], [

            / wv\).+(chrome)\/([\w\.]+)/i                                       // Chrome WebView
            ], [[NAME, CHROME+' WebView'], VERSION], [

            /droid.+ version\/([\w\.]+)\b.+(?:mobile safari|safari)/i           // Android Browser
            ], [VERSION, [NAME, 'Android' + SUFFIX_BROWSER]], [

            /chrome\/([\w\.]+) mobile/i                                         // Chrome Mobile
            ], [VERSION, [NAME, PREFIX_MOBILE + 'Chrome']], [

            /(chrome|omniweb|arora|[tizenoka]{5} ?browser)\/v?([\w\.]+)/i       // Chrome/OmniWeb/Arora/Tizen/Nokia
            ], [NAME, VERSION], [

            /version\/([\w\.\,]+) .*mobile(?:\/\w+ | ?)safari/i                 // Safari Mobile
            ], [VERSION, [NAME, PREFIX_MOBILE + 'Safari']], [
            /iphone .*mobile(?:\/\w+ | ?)safari/i
            ], [[NAME, PREFIX_MOBILE + 'Safari']], [
            /version\/([\w\.\,]+) .*(safari)/i                                  // Safari
            ], [VERSION, NAME], [
            /webkit.+?(mobile ?safari|safari)(\/[\w\.]+)/i                      // Safari < 3.0
            ], [NAME, [VERSION, '1']], [

            /(webkit|khtml)\/([\w\.]+)/i
            ], [NAME, VERSION], [

            // Gecko based
            /(?:mobile|tablet);.*(firefox)\/([\w\.-]+)/i                        // Firefox Mobile
            ], [[NAME, PREFIX_MOBILE + FIREFOX], VERSION], [
            /(navigator|netscape\d?)\/([-\w\.]+)/i                              // Netscape
            ], [[NAME, 'Netscape'], VERSION], [
            /(wolvic|librewolf)\/([\w\.]+)/i                                    // Wolvic/LibreWolf
            ], [NAME, VERSION], [
            /mobile vr; rv:([\w\.]+)\).+firefox/i                               // Firefox Reality
            ], [VERSION, [NAME, FIREFOX+' Reality']], [
            /ekiohf.+(flow)\/([\w\.]+)/i,                                       // Flow
            /(swiftfox)/i,                                                      // Swiftfox
            /(icedragon|iceweasel|camino|chimera|fennec|maemo browser|minimo|conkeror)[\/ ]?([\w\.\+]+)/i,
                                                                                // IceDragon/Iceweasel/Camino/Chimera/Fennec/Maemo/Minimo/Conkeror
            /(seamonkey|k-meleon|icecat|iceape|firebird|phoenix|palemoon|basilisk|waterfox)\/([-\w\.]+)$/i,
                                                                                // Firefox/SeaMonkey/K-Meleon/IceCat/IceApe/Firebird/Phoenix
            /(firefox)\/([\w\.]+)/i,                                            // Other Firefox-based
            /(mozilla)\/([\w\.]+) .+rv\:.+gecko\/\d+/i,                         // Mozilla

            // Other
            /(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|obigo|mosaic|(?:go|ice|up)[\. ]?browser)[-\/ ]?v?([\w\.]+)/i,
                                                                                // Polaris/Lynx/Dillo/iCab/Doris/Amaya/w3m/NetSurf/Obigo/Mosaic/Go/ICE/UP.Browser
            /\b(links) \(([\w\.]+)/i                                            // Links
            ], [NAME, [VERSION, /_/g, '.']], [
            
            /(cobalt)\/([\w\.]+)/i                                              // Cobalt
            ], [NAME, [VERSION, /[^\d\.]+./, EMPTY]]
        ],

        cpu : [[

            /\b(?:(amd|x|x86[-_]?|wow|win)64)\b/i                               // AMD64 (x64)
            ], [[ARCHITECTURE, 'amd64']], [

            /(ia32(?=;))/i,                                                     // IA32 (quicktime)
            /((?:i[346]|x)86)[;\)]/i                                            // IA32 (x86)
            ], [[ARCHITECTURE, 'ia32']], [

            /\b(aarch64|arm(v?8e?l?|_?64))\b/i                                  // ARM64
            ], [[ARCHITECTURE, 'arm64']], [

            /\b(arm(?:v[67])?ht?n?[fl]p?)\b/i                                   // ARMHF
            ], [[ARCHITECTURE, 'armhf']], [

            // PocketPC mistakenly identified as PowerPC
            /windows (ce|mobile); ppc;/i
            ], [[ARCHITECTURE, 'arm']], [

            /((?:ppc|powerpc)(?:64)?)(?: mac|;|\))/i                            // PowerPC
            ], [[ARCHITECTURE, /ower/, EMPTY, lowerize]], [

            /(sun4\w)[;\)]/i                                                    // SPARC
            ], [[ARCHITECTURE, 'sparc']], [

            /((?:avr32|ia64(?=;))|68k(?=\))|\barm(?=v(?:[1-7]|[5-7]1)l?|;|eabi)|(?=atmel )avr|(?:irix|mips|sparc)(?:64)?\b|pa-risc)/i
                                                                                // IA64, 68K, ARM/64, AVR/32, IRIX/64, MIPS/64, SPARC/64, PA-RISC
            ], [[ARCHITECTURE, lowerize]]
        ],

        device : [[

            //////////////////////////
            // MOBILES & TABLETS
            /////////////////////////

            // Samsung
            /\b(sch-i[89]0\d|shw-m380s|sm-[ptx]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus 10)/i
            ], [MODEL, [VENDOR, SAMSUNG], [TYPE, TABLET]], [
            /\b((?:s[cgp]h|gt|sm)-(?![lr])\w+|sc[g-]?[\d]+a?|galaxy nexus)/i,
            /samsung[- ]((?!sm-[lr])[-\w]+)/i,
            /sec-(sgh\w+)/i
            ], [MODEL, [VENDOR, SAMSUNG], [TYPE, MOBILE]], [

            // Apple
            /(?:\/|\()(ip(?:hone|od)[\w, ]*)(?:\/|;)/i                          // iPod/iPhone
            ], [MODEL, [VENDOR, APPLE], [TYPE, MOBILE]], [
            /\((ipad);[-\w\),; ]+apple/i,                                       // iPad
            /applecoremedia\/[\w\.]+ \((ipad)/i,
            /\b(ipad)\d\d?,\d\d?[;\]].+ios/i
            ], [MODEL, [VENDOR, APPLE], [TYPE, TABLET]], [
            /(macintosh);/i
            ], [MODEL, [VENDOR, APPLE]], [

            // Sharp
            /\b(sh-?[altvz]?\d\d[a-ekm]?)/i
            ], [MODEL, [VENDOR, SHARP], [TYPE, MOBILE]], [

            // Honor
            /(?:honor)([-\w ]+)[;\)]/i
            ], [MODEL, [VENDOR, HONOR], [TYPE, MOBILE]], [

            // Huawei
            /\b((?:ag[rs][23]?|bah2?|sht?|btv)-a?[lw]\d{2})\b(?!.+d\/s)/i
            ], [MODEL, [VENDOR, HUAWEI], [TYPE, TABLET]], [
            /(?:huawei)([-\w ]+)[;\)]/i,
            /\b(nexus 6p|\w{2,4}e?-[atu]?[ln][\dx][012359c][adn]?)\b(?!.+d\/s)/i
            ], [MODEL, [VENDOR, HUAWEI], [TYPE, MOBILE]], [

            // Xiaomi
            /\b(poco[\w ]+|m2\d{3}j\d\d[a-z]{2})(?: bui|\))/i,                  // Xiaomi POCO
            /\b; (\w+) build\/hm\1/i,                                           // Xiaomi Hongmi 'numeric' models
            /\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i,                             // Xiaomi Hongmi
            /\b(redmi[\-_ ]?(?:note|k)?[\w_ ]+)(?: bui|\))/i,                   // Xiaomi Redmi
            /oid[^\)]+; (m?[12][0-389][01]\w{3,6}[c-y])( bui|; wv|\))/i,        // Xiaomi Redmi 'numeric' models
            /\b(mi[-_ ]?(?:a\d|one|one[_ ]plus|note lte|max|cc)?[_ ]?(?:\d?\w?)[_ ]?(?:plus|se|lite|pro)?)(?: bui|\))/i // Xiaomi Mi
            ], [[MODEL, /_/g, ' '], [VENDOR, XIAOMI], [TYPE, MOBILE]], [
            /oid[^\)]+; (2\d{4}(283|rpbf)[cgl])( bui|\))/i,                     // Redmi Pad
            /\b(mi[-_ ]?(?:pad)(?:[\w_ ]+))(?: bui|\))/i                        // Mi Pad tablets
            ],[[MODEL, /_/g, ' '], [VENDOR, XIAOMI], [TYPE, TABLET]], [

            // OPPO
            /; (\w+) bui.+ oppo/i,
            /\b(cph[12]\d{3}|p(?:af|c[al]|d\w|e[ar])[mt]\d0|x9007|a101op)\b/i
            ], [MODEL, [VENDOR, 'OPPO'], [TYPE, MOBILE]], [
            /\b(opd2\d{3}a?) bui/i
            ], [MODEL, [VENDOR, 'OPPO'], [TYPE, TABLET]], [

            // Vivo
            /vivo (\w+)(?: bui|\))/i,
            /\b(v[12]\d{3}\w?[at])(?: bui|;)/i
            ], [MODEL, [VENDOR, 'Vivo'], [TYPE, MOBILE]], [

            // Realme
            /\b(rmx[1-3]\d{3})(?: bui|;|\))/i
            ], [MODEL, [VENDOR, 'Realme'], [TYPE, MOBILE]], [

            // Motorola
            /\b(milestone|droid(?:[2-4x]| (?:bionic|x2|pro|razr))?:?( 4g)?)\b[\w ]+build\//i,
            /\bmot(?:orola)?[- ](\w*)/i,
            /((?:moto[\w\(\) ]+|xt\d{3,4}|nexus 6)(?= bui|\)))/i
            ], [MODEL, [VENDOR, MOTOROLA], [TYPE, MOBILE]], [
            /\b(mz60\d|xoom[2 ]{0,2}) build\//i
            ], [MODEL, [VENDOR, MOTOROLA], [TYPE, TABLET]], [

            // LG
            /((?=lg)?[vl]k\-?\d{3}) bui| 3\.[-\w; ]{10}lg?-([06cv9]{3,4})/i
            ], [MODEL, [VENDOR, LG], [TYPE, TABLET]], [
            /(lm(?:-?f100[nv]?|-[\w\.]+)(?= bui|\))|nexus [45])/i,
            /\blg[-e;\/ ]+((?!browser|netcast|android tv)\w+)/i,
            /\blg-?([\d\w]+) bui/i
            ], [MODEL, [VENDOR, LG], [TYPE, MOBILE]], [

            // Lenovo
            /(ideatab[-\w ]+)/i,
            /lenovo ?(s[56]000[-\w]+|tab(?:[\w ]+)|yt[-\d\w]{6}|tb[-\d\w]{6})/i
            ], [MODEL, [VENDOR, LENOVO], [TYPE, TABLET]], [

            // Nokia
            /(?:maemo|nokia).*(n900|lumia \d+)/i,
            /nokia[-_ ]?([-\w\.]*)/i
            ], [[MODEL, /_/g, ' '], [VENDOR, 'Nokia'], [TYPE, MOBILE]], [

            // Google
            /(pixel c)\b/i                                                      // Google Pixel C
            ], [MODEL, [VENDOR, GOOGLE], [TYPE, TABLET]], [
            /droid.+; (pixel[\daxl ]{0,6})(?: bui|\))/i                         // Google Pixel
            ], [MODEL, [VENDOR, GOOGLE], [TYPE, MOBILE]], [

            // Sony
            /droid.+; (a?\d[0-2]{2}so|[c-g]\d{4}|so[-gl]\w+|xq-a\w[4-7][12])(?= bui|\).+chrome\/(?![1-6]{0,1}\d\.))/i
            ], [MODEL, [VENDOR, SONY], [TYPE, MOBILE]], [
            /sony tablet [ps]/i,
            /\b(?:sony)?sgp\w+(?: bui|\))/i
            ], [[MODEL, 'Xperia Tablet'], [VENDOR, SONY], [TYPE, TABLET]], [

            // OnePlus
            / (kb2005|in20[12]5|be20[12][59])\b/i,
            /(?:one)?(?:plus)? (a\d0\d\d)(?: b|\))/i
            ], [MODEL, [VENDOR, 'OnePlus'], [TYPE, MOBILE]], [

            // Amazon
            /(alexa)webm/i,
            /(kf[a-z]{2}wi|aeo(?!bc)\w\w)( bui|\))/i,                           // Kindle Fire without Silk / Echo Show
            /(kf[a-z]+)( bui|\)).+silk\//i                                      // Kindle Fire HD
            ], [MODEL, [VENDOR, AMAZON], [TYPE, TABLET]], [
            /((?:sd|kf)[0349hijorstuw]+)( bui|\)).+silk\//i                     // Fire Phone
            ], [[MODEL, /(.+)/g, 'Fire Phone $1'], [VENDOR, AMAZON], [TYPE, MOBILE]], [

            // BlackBerry
            /(playbook);[-\w\),; ]+(rim)/i                                      // BlackBerry PlayBook
            ], [MODEL, VENDOR, [TYPE, TABLET]], [
            /\b((?:bb[a-f]|st[hv])100-\d)/i,
            /\(bb10; (\w+)/i                                                    // BlackBerry 10
            ], [MODEL, [VENDOR, BLACKBERRY], [TYPE, MOBILE]], [

            // Asus
            /(?:\b|asus_)(transfo[prime ]{4,10} \w+|eeepc|slider \w+|nexus 7|padfone|p00[cj])/i
            ], [MODEL, [VENDOR, ASUS], [TYPE, TABLET]], [
            / (z[bes]6[027][012][km][ls]|zenfone \d\w?)\b/i
            ], [MODEL, [VENDOR, ASUS], [TYPE, MOBILE]], [

            // HTC
            /(nexus 9)/i                                                        // HTC Nexus 9
            ], [MODEL, [VENDOR, 'HTC'], [TYPE, TABLET]], [
            /(htc)[-;_ ]{1,2}([\w ]+(?=\)| bui)|\w+)/i,                         // HTC

            // ZTE
            /(zte)[- ]([\w ]+?)(?: bui|\/|\))/i,
            /(alcatel|geeksphone|nexian|panasonic(?!(?:;|\.))|sony(?!-bra))[-_ ]?([-\w]*)/i         // Alcatel/GeeksPhone/Nexian/Panasonic/Sony
            ], [VENDOR, [MODEL, /_/g, ' '], [TYPE, MOBILE]], [

            // TCL
            /tcl (xess p17aa)/i,
            /droid [\w\.]+; ((?:8[14]9[16]|9(?:0(?:48|60|8[01])|1(?:3[27]|66)|2(?:6[69]|9[56])|466))[gqswx])(_\w(\w|\w\w))?(\)| bui)/i
            ], [MODEL, [VENDOR, 'TCL'], [TYPE, TABLET]], [
            /droid [\w\.]+; (418(?:7d|8v)|5087z|5102l|61(?:02[dh]|25[adfh]|27[ai]|56[dh]|59k|65[ah])|a509dl|t(?:43(?:0w|1[adepqu])|50(?:6d|7[adju])|6(?:09dl|10k|12b|71[efho]|76[hjk])|7(?:66[ahju]|67[hw]|7[045][bh]|71[hk]|73o|76[ho]|79w|81[hks]?|82h|90[bhsy]|99b)|810[hs]))(_\w(\w|\w\w))?(\)| bui)/i
            ], [MODEL, [VENDOR, 'TCL'], [TYPE, MOBILE]], [

            // itel
            /(itel) ((\w+))/i
            ], [[VENDOR, lowerize], MODEL, [TYPE, strMapper, { 'tablet' : ['p10001l', 'w7001'], '*' : 'mobile' }]], [

            // Acer
            /droid.+; ([ab][1-7]-?[0178a]\d\d?)/i
            ], [MODEL, [VENDOR, 'Acer'], [TYPE, TABLET]], [

            // Meizu
            /droid.+; (m[1-5] note) bui/i,
            /\bmz-([-\w]{2,})/i
            ], [MODEL, [VENDOR, 'Meizu'], [TYPE, MOBILE]], [
                
            // Ulefone
            /; ((?:power )?armor(?:[\w ]{0,8}))(?: bui|\))/i
            ], [MODEL, [VENDOR, 'Ulefone'], [TYPE, MOBILE]], [

            // Energizer
            /; (energy ?\w+)(?: bui|\))/i,
            /; energizer ([\w ]+)(?: bui|\))/i
            ], [MODEL, [VENDOR, 'Energizer'], [TYPE, MOBILE]], [

            // Cat
            /; cat (b35);/i,
            /; (b15q?|s22 flip|s48c|s62 pro)(?: bui|\))/i
            ], [MODEL, [VENDOR, 'Cat'], [TYPE, MOBILE]], [

            // Smartfren
            /((?:new )?andromax[\w- ]+)(?: bui|\))/i
            ], [MODEL, [VENDOR, 'Smartfren'], [TYPE, MOBILE]], [

            // Nothing
            /droid.+; (a(?:015|06[35]|142p?))/i
            ], [MODEL, [VENDOR, 'Nothing'], [TYPE, MOBILE]], [

            // MIXED
            /(blackberry|benq|palm(?=\-)|sonyericsson|acer|asus|dell|meizu|motorola|polytron|infinix|tecno|micromax|advan)[-_ ]?([-\w]*)/i,
                                                                                // BlackBerry/BenQ/Palm/Sony-Ericsson/Acer/Asus/Dell/Meizu/Motorola/Polytron/Infinix/Tecno/Micromax/Advan
            /; (imo) ((?!tab)[\w ]+?)(?: bui|\))/i,                             // IMO
            /(hp) ([\w ]+\w)/i,                                                 // HP iPAQ
            /(asus)-?(\w+)/i,                                                   // Asus
            /(microsoft); (lumia[\w ]+)/i,                                      // Microsoft Lumia
            /(lenovo)[-_ ]?([-\w]+)/i,                                          // Lenovo
            /(jolla)/i,                                                         // Jolla
            /(oppo) ?([\w ]+) bui/i                                             // OPPO
            ], [VENDOR, MODEL, [TYPE, MOBILE]], [

            /(imo) (tab \w+)/i,                                                 // IMO
            /(kobo)\s(ereader|touch)/i,                                         // Kobo
            /(archos) (gamepad2?)/i,                                            // Archos
            /(hp).+(touchpad(?!.+tablet)|tablet)/i,                             // HP TouchPad
            /(kindle)\/([\w\.]+)/i                                              // Kindle
            ], [VENDOR, MODEL, [TYPE, TABLET]], [

            /(surface duo)/i                                                    // Surface Duo
            ], [MODEL, [VENDOR, MICROSOFT], [TYPE, TABLET]], [
            /droid [\d\.]+; (fp\du?)(?: b|\))/i                                 // Fairphone
            ], [MODEL, [VENDOR, 'Fairphone'], [TYPE, MOBILE]], [
            /(shield[\w ]+) b/i                                                 // Nvidia Shield Tablets
            ], [MODEL, [VENDOR, 'Nvidia'], [TYPE, TABLET]], [
            /(sprint) (\w+)/i                                                   // Sprint Phones
            ], [VENDOR, MODEL, [TYPE, MOBILE]], [
            /(kin\.[onetw]{3})/i                                                // Microsoft Kin
            ], [[MODEL, /\./g, ' '], [VENDOR, MICROSOFT], [TYPE, MOBILE]], [
            /droid.+; ([c6]+|et5[16]|mc[239][23]x?|vc8[03]x?)\)/i               // Zebra
            ], [MODEL, [VENDOR, ZEBRA], [TYPE, TABLET]], [
            /droid.+; (ec30|ps20|tc[2-8]\d[kx])\)/i
            ], [MODEL, [VENDOR, ZEBRA], [TYPE, MOBILE]], [

            ///////////////////
            // SMARTTVS
            ///////////////////

            /smart-tv.+(samsung)/i                                              // Samsung
            ], [VENDOR, [TYPE, SMARTTV]], [
            /hbbtv.+maple;(\d+)/i
            ], [[MODEL, /^/, 'SmartTV'], [VENDOR, SAMSUNG], [TYPE, SMARTTV]], [
            /(nux; netcast.+smarttv|lg (netcast\.tv-201\d|android tv))/i        // LG SmartTV
            ], [[VENDOR, LG], [TYPE, SMARTTV]], [
            /(apple) ?tv/i                                                      // Apple TV
            ], [VENDOR, [MODEL, APPLE+' TV'], [TYPE, SMARTTV]], [
            /crkey.*devicetype\/chromecast/i                                    // Google Chromecast Third Generation
            ], [[MODEL, CHROMECAST+' Third Generation'], [VENDOR, GOOGLE], [TYPE, SMARTTV]], [
            /crkey.*devicetype\/([^/]*)/i                                       // Google Chromecast with specific device type
            ], [[MODEL, /^/, 'Chromecast '], [VENDOR, GOOGLE], [TYPE, SMARTTV]], [
            /fuchsia.*crkey/i                                                   // Google Chromecast Nest Hub
            ], [[MODEL, CHROMECAST+' Nest Hub'], [VENDOR, GOOGLE], [TYPE, SMARTTV]], [
            /crkey/i                                                            // Google Chromecast, Linux-based or unknown
            ], [[MODEL, CHROMECAST], [VENDOR, GOOGLE], [TYPE, SMARTTV]], [
            /droid.+aft(\w+)( bui|\))/i                                         // Fire TV
            ], [MODEL, [VENDOR, AMAZON], [TYPE, SMARTTV]], [
            /\(dtv[\);].+(aquos)/i,
            /(aquos-tv[\w ]+)\)/i                                               // Sharp
            ], [MODEL, [VENDOR, SHARP], [TYPE, SMARTTV]],[
            /(bravia[\w ]+)( bui|\))/i                                          // Sony
            ], [MODEL, [VENDOR, SONY], [TYPE, SMARTTV]], [
            /(mitv-\w{5}) bui/i                                                 // Xiaomi
            ], [MODEL, [VENDOR, XIAOMI], [TYPE, SMARTTV]], [
            /Hbbtv.*(technisat) (.*);/i                                         // TechniSAT
            ], [VENDOR, MODEL, [TYPE, SMARTTV]], [
            /\b(roku)[\dx]*[\)\/]((?:dvp-)?[\d\.]*)/i,                          // Roku
            /hbbtv\/\d+\.\d+\.\d+ +\([\w\+ ]*; *([\w\d][^;]*);([^;]*)/i         // HbbTV devices
            ], [[VENDOR, trim], [MODEL, trim], [TYPE, SMARTTV]], [
            /\b(android tv|smart[- ]?tv|opera tv|tv; rv:)\b/i                   // SmartTV from Unidentified Vendors
            ], [[TYPE, SMARTTV]], [

            ///////////////////
            // CONSOLES
            ///////////////////

            /(ouya)/i,                                                          // Ouya
            /(nintendo) (\w+)/i                                                 // Nintendo
            ], [VENDOR, MODEL, [TYPE, CONSOLE]], [
            /droid.+; (shield) bui/i                                            // Nvidia
            ], [MODEL, [VENDOR, 'Nvidia'], [TYPE, CONSOLE]], [
            /(playstation \w+)/i                                                // Playstation
            ], [MODEL, [VENDOR, SONY], [TYPE, CONSOLE]], [
            /\b(xbox(?: one)?(?!; xbox))[\); ]/i                                // Microsoft Xbox
            ], [MODEL, [VENDOR, MICROSOFT], [TYPE, CONSOLE]], [

            ///////////////////
            // WEARABLES
            ///////////////////

            /\b(sm-[lr]\d\d[05][fnuw]?s?)\b/i                                   // Samsung Galaxy Watch
            ], [MODEL, [VENDOR, SAMSUNG], [TYPE, WEARABLE]], [
            /((pebble))app/i                                                    // Pebble
            ], [VENDOR, MODEL, [TYPE, WEARABLE]], [
            /(watch)(?: ?os[,\/]|\d,\d\/)[\d\.]+/i                              // Apple Watch
            ], [MODEL, [VENDOR, APPLE], [TYPE, WEARABLE]], [
            /droid.+; (wt63?0{2,3})\)/i
            ], [MODEL, [VENDOR, ZEBRA], [TYPE, WEARABLE]], [

            ///////////////////
            // XR
            ///////////////////

            /droid.+; (glass) \d/i                                              // Google Glass
            ], [MODEL, [VENDOR, GOOGLE], [TYPE, XR]], [
            /(pico) (4|neo3(?: link|pro)?)/i                                    // Pico
            ], [VENDOR, MODEL, [TYPE, XR]], [
            /; (quest( \d| pro)?)/i                                             // Oculus Quest
            ], [MODEL, [VENDOR, FACEBOOK], [TYPE, XR]], [

            ///////////////////
            // EMBEDDED
            ///////////////////

            /(tesla)(?: qtcarbrowser|\/[-\w\.]+)/i                              // Tesla
            ], [VENDOR, [TYPE, EMBEDDED]], [
            /(aeobc)\b/i                                                        // Echo Dot
            ], [MODEL, [VENDOR, AMAZON], [TYPE, EMBEDDED]], [

            ////////////////////
            // MIXED (GENERIC)
            ///////////////////

            /droid .+?; ([^;]+?)(?: bui|; wv\)|\) applew).+? mobile safari/i    // Android Phones from Unidentified Vendors
            ], [MODEL, [TYPE, MOBILE]], [
            /droid .+?; ([^;]+?)(?: bui|\) applew).+?(?! mobile) safari/i       // Android Tablets from Unidentified Vendors
            ], [MODEL, [TYPE, TABLET]], [
            /\b((tablet|tab)[;\/]|focus\/\d(?!.+mobile))/i                      // Unidentifiable Tablet
            ], [[TYPE, TABLET]], [
            /(phone|mobile(?:[;\/]| [ \w\/\.]*safari)|pda(?=.+windows ce))/i    // Unidentifiable Mobile
            ], [[TYPE, MOBILE]], [
            /(android[-\w\. ]{0,9});.+buil/i                                    // Generic Android Device
            ], [MODEL, [VENDOR, 'Generic']]
        ],

        engine : [[

            /windows.+ edge\/([\w\.]+)/i                                       // EdgeHTML
            ], [VERSION, [NAME, EDGE+'HTML']], [

            /(arkweb)\/([\w\.]+)/i                                              // ArkWeb
            ], [NAME, VERSION], [

            /webkit\/537\.36.+chrome\/(?!27)([\w\.]+)/i                         // Blink
            ], [VERSION, [NAME, 'Blink']], [

            /(presto)\/([\w\.]+)/i,                                             // Presto
            /(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna|servo)\/([\w\.]+)/i, // WebKit/Trident/NetFront/NetSurf/Amaya/Lynx/w3m/Goanna/Servo
            /ekioh(flow)\/([\w\.]+)/i,                                          // Flow
            /(khtml|tasman|links)[\/ ]\(?([\w\.]+)/i,                           // KHTML/Tasman/Links
            /(icab)[\/ ]([23]\.[\d\.]+)/i,                                      // iCab
            /\b(libweb)/i
            ], [NAME, VERSION], [

            /rv\:([\w\.]{1,9})\b.+(gecko)/i                                     // Gecko
            ], [VERSION, NAME]
        ],

        os : [[

            // Windows
            /microsoft (windows) (vista|xp)/i                                   // Windows (iTunes)
            ], [NAME, VERSION], [
            /(windows (?:phone(?: os)?|mobile))[\/ ]?([\d\.\w ]*)/i             // Windows Phone
            ], [NAME, [VERSION, strMapper, windowsVersionMap]], [
            /windows nt 6\.2; (arm)/i,                                        // Windows RT
            /windows[\/ ]?([ntce\d\. ]+\w)(?!.+xbox)/i,
            /(?:win(?=3|9|n)|win 9x )([nt\d\.]+)/i
            ], [[VERSION, strMapper, windowsVersionMap], [NAME, WINDOWS]], [

            // iOS/macOS
            /ip[honead]{2,4}\b(?:.*os ([\w]+) like mac|; opera)/i,              // iOS
            /(?:ios;fbsv\/|iphone.+ios[\/ ])([\d\.]+)/i,
            /cfnetwork\/.+darwin/i
            ], [[VERSION, /_/g, '.'], [NAME, 'iOS']], [
            /(mac os x) ?([\w\. ]*)/i,
            /(macintosh|mac_powerpc\b)(?!.+haiku)/i                             // Mac OS
            ], [[NAME, 'macOS'], [VERSION, /_/g, '.']], [

            // Google Chromecast
            /android ([\d\.]+).*crkey/i                                         // Google Chromecast, Android-based
            ], [VERSION, [NAME, CHROMECAST + ' Android']], [
            /fuchsia.*crkey\/([\d\.]+)/i                                        // Google Chromecast, Fuchsia-based
            ], [VERSION, [NAME, CHROMECAST + ' Fuchsia']], [
            /crkey\/([\d\.]+).*devicetype\/smartspeaker/i                       // Google Chromecast, Linux-based Smart Speaker
            ], [VERSION, [NAME, CHROMECAST + ' SmartSpeaker']], [
            /linux.*crkey\/([\d\.]+)/i                                          // Google Chromecast, Legacy Linux-based
            ], [VERSION, [NAME, CHROMECAST + ' Linux']], [
            /crkey\/([\d\.]+)/i                                                 // Google Chromecast, unknown
            ], [VERSION, [NAME, CHROMECAST]], [

            // Mobile OSes
            /droid ([\w\.]+)\b.+(android[- ]x86|harmonyos)/i                    // Android-x86/HarmonyOS
            ], [VERSION, NAME], [                                               // Android/WebOS/QNX/Bada/RIM/Maemo/MeeGo/Sailfish OS/OpenHarmony
            /(android|webos|qnx|bada|rim tablet os|maemo|meego|sailfish|openharmony)[-\/ ]?([\w\.]*)/i,
            /(blackberry)\w*\/([\w\.]*)/i,                                      // Blackberry
            /(tizen|kaios)[\/ ]([\w\.]+)/i,                                     // Tizen/KaiOS
            /\((series40);/i                                                    // Series 40
            ], [NAME, VERSION], [
            /\(bb(10);/i                                                        // BlackBerry 10
            ], [VERSION, [NAME, BLACKBERRY]], [
            /(?:symbian ?os|symbos|s60(?=;)|series60)[-\/ ]?([\w\.]*)/i         // Symbian
            ], [VERSION, [NAME, 'Symbian']], [
            /mozilla\/[\d\.]+ \((?:mobile|tablet|tv|mobile; [\w ]+); rv:.+ gecko\/([\w\.]+)/i // Firefox OS
            ], [VERSION, [NAME, FIREFOX+' OS']], [
            /web0s;.+rt(tv)/i,
            /\b(?:hp)?wos(?:browser)?\/([\w\.]+)/i                              // WebOS
            ], [VERSION, [NAME, 'webOS']], [
            /watch(?: ?os[,\/]|\d,\d\/)([\d\.]+)/i                              // watchOS
            ], [VERSION, [NAME, 'watchOS']], [

            // Google ChromeOS
            /(cros) [\w]+(?:\)| ([\w\.]+)\b)/i                                  // Chromium OS
            ], [[NAME, "Chrome OS"], VERSION],[

            // Smart TVs
            /panasonic;(viera)/i,                                               // Panasonic Viera
            /(netrange)mmh/i,                                                   // Netrange
            /(nettv)\/(\d+\.[\w\.]+)/i,                                         // NetTV

            // Console
            /(nintendo|playstation) (\w+)/i,                                    // Nintendo/Playstation
            /(xbox); +xbox ([^\);]+)/i,                                         // Microsoft Xbox (360, One, X, S, Series X, Series S)
            /(pico) .+os([\w\.]+)/i,                                            // Pico

            // Other
            /\b(joli|palm)\b ?(?:os)?\/?([\w\.]*)/i,                            // Joli/Palm
            /(mint)[\/\(\) ]?(\w*)/i,                                           // Mint
            /(mageia|vectorlinux)[; ]/i,                                        // Mageia/VectorLinux
            /([kxln]?ubuntu|debian|suse|opensuse|gentoo|arch(?= linux)|slackware|fedora|mandriva|centos|pclinuxos|red ?hat|zenwalk|linpus|raspbian|plan 9|minix|risc os|contiki|deepin|manjaro|elementary os|sabayon|linspire)(?: gnu\/linux)?(?: enterprise)?(?:[- ]linux)?(?:-gnu)?[-\/ ]?(?!chrom|package)([-\w\.]*)/i,
                                                                                // Ubuntu/Debian/SUSE/Gentoo/Arch/Slackware/Fedora/Mandriva/CentOS/PCLinuxOS/RedHat/Zenwalk/Linpus/Raspbian/Plan9/Minix/RISCOS/Contiki/Deepin/Manjaro/elementary/Sabayon/Linspire
            /(hurd|linux) ?([\w\.]*)/i,                                         // Hurd/Linux
            /(gnu) ?([\w\.]*)/i,                                                // GNU
            /\b([-frentopcghs]{0,5}bsd|dragonfly)[\/ ]?(?!amd|[ix346]{1,2}86)([\w\.]*)/i, // FreeBSD/NetBSD/OpenBSD/PC-BSD/GhostBSD/DragonFly
            /(haiku) (\w+)/i                                                    // Haiku
            ], [NAME, VERSION], [
            /(sunos) ?([\w\.\d]*)/i                                             // Solaris
            ], [[NAME, 'Solaris'], VERSION], [
            /((?:open)?solaris)[-\/ ]?([\w\.]*)/i,                              // Solaris
            /(aix) ((\d)(?=\.|\)| )[\w\.])*/i,                                  // AIX
            /\b(beos|os\/2|amigaos|morphos|openvms|fuchsia|hp-ux|serenityos)/i, // BeOS/OS2/AmigaOS/MorphOS/OpenVMS/Fuchsia/HP-UX/SerenityOS
            /(unix) ?([\w\.]*)/i                                                // UNIX
            ], [NAME, VERSION]
        ]
    };

    /////////////////
    // Factories
    ////////////////

    var defaultProps = (function () {
            var props = { init : {}, isIgnore : {}, isIgnoreRgx : {}, toString : {}};
            setProps.call(props.init, [
                [UA_BROWSER, [NAME, VERSION, MAJOR, TYPE]],
                [UA_CPU, [ARCHITECTURE]],
                [UA_DEVICE, [TYPE, MODEL, VENDOR]],
                [UA_ENGINE, [NAME, VERSION]],
                [UA_OS, [NAME, VERSION]]
            ]);
            setProps.call(props.isIgnore, [
                [UA_BROWSER, [VERSION, MAJOR]],
                [UA_ENGINE, [VERSION]],
                [UA_OS, [VERSION]]
            ]);
            setProps.call(props.isIgnoreRgx, [
                [UA_BROWSER, / ?browser$/i],
                [UA_OS, / ?os$/i]
            ]);
            setProps.call(props.toString, [
                [UA_BROWSER, [NAME, VERSION]],
                [UA_CPU, [ARCHITECTURE]],
                [UA_DEVICE, [VENDOR, MODEL]],
                [UA_ENGINE, [NAME, VERSION]],
                [UA_OS, [NAME, VERSION]]
            ]);
            return props;
    })();

    var createIData = function (item, itemType) {

        var init_props = defaultProps.init[itemType],
            is_ignoreProps = defaultProps.isIgnore[itemType] || 0,
            is_ignoreRgx = defaultProps.isIgnoreRgx[itemType] || 0,
            toString_props = defaultProps.toString[itemType] || 0;

        function IData () {
            setProps.call(this, init_props);
        }

        IData.prototype.getItem = function () {
            return item;
        };

        IData.prototype.withClientHints = function () {

            // nodejs / non-client-hints browsers
            if (!NAVIGATOR_UADATA) {
                return item
                        .parseCH()
                        .get();
            }

            // browsers based on chromium 85+
            return NAVIGATOR_UADATA
                    .getHighEntropyValues(CH_ALL_VALUES)
                    .then(function (res) {
                        return item
                                .setCH(new UACHData(res, false))
                                .parseCH()
                                .get();
            });
        };

        IData.prototype.withFeatureCheck = function () {
            return item.detectFeature().get();
        };

        if (itemType != UA_RESULT) {
            IData.prototype.is = function (strToCheck) {
                var is = false;
                for (var i in this) {
                    if (this.hasOwnProperty(i) && !has(is_ignoreProps, i) && lowerize(is_ignoreRgx ? strip(is_ignoreRgx, this[i]) : this[i]) == lowerize(is_ignoreRgx ? strip(is_ignoreRgx, strToCheck) : strToCheck)) {
                        is = true;
                        if (strToCheck != UNDEF_TYPE) break;
                    } else if (strToCheck == UNDEF_TYPE && is) {
                        is = !is;
                        break;
                    }
                }
                return is;
            };
            IData.prototype.toString = function () {
                var str = EMPTY;
                for (var i in toString_props) {
                    if (typeof(this[toString_props[i]]) !== UNDEF_TYPE) {
                        str += (str ? ' ' : EMPTY) + this[toString_props[i]];
                    }
                }
                return str || UNDEF_TYPE;
            };
        }

        if (!NAVIGATOR_UADATA) {
            IData.prototype.then = function (cb) { 
                var that = this;
                var IDataResolve = function () {
                    for (var prop in that) {
                        if (that.hasOwnProperty(prop)) {
                            this[prop] = that[prop];
                        }
                    }
                };
                IDataResolve.prototype = {
                    is : IData.prototype.is,
                    toString : IData.prototype.toString
                };
                var resolveData = new IDataResolve();
                cb(resolveData);
                return resolveData;
            };
        }

        return new IData();
    };

    /////////////////
    // Constructor
    ////////////////

    function UACHData (uach, isHttpUACH) {
        uach = uach || {};
        setProps.call(this, CH_ALL_VALUES);
        if (isHttpUACH) {
            setProps.call(this, [
                [BRANDS, itemListToArray(uach[CH_HEADER])],
                [FULLVERLIST, itemListToArray(uach[CH_HEADER_FULL_VER_LIST])],
                [MOBILE, /\?1/.test(uach[CH_HEADER_MOBILE])],
                [MODEL, stripQuotes(uach[CH_HEADER_MODEL])],
                [PLATFORM, stripQuotes(uach[CH_HEADER_PLATFORM])],
                [PLATFORMVER, stripQuotes(uach[CH_HEADER_PLATFORM_VER])],
                [ARCHITECTURE, stripQuotes(uach[CH_HEADER_ARCH])],
                [FORMFACTORS, itemListToArray(uach[CH_HEADER_FORM_FACTORS])],
                [BITNESS, stripQuotes(uach[CH_HEADER_BITNESS])]
            ]);
        } else {
            for (var prop in uach) {
                if(this.hasOwnProperty(prop) && typeof uach[prop] !== UNDEF_TYPE) this[prop] = uach[prop];
            }
        }
    }

    function UAItem (itemType, ua, rgxMap, uaCH) {

        this.get = function (prop) {
            if (!prop) return this.data;
            return this.data.hasOwnProperty(prop) ? this.data[prop] : undefined;
        };

        this.set = function (prop, val) {
            this.data[prop] = val;
            return this;
        };

        this.setCH = function (ch) {
            this.uaCH = ch;
            return this;
        };

        this.detectFeature = function () {
            if (NAVIGATOR && NAVIGATOR.userAgent == this.ua) {
                switch (this.itemType) {
                    case UA_BROWSER:
                        // Brave-specific detection
                        if (NAVIGATOR.brave && typeof NAVIGATOR.brave.isBrave == FUNC_TYPE) {
                            this.set(NAME, 'Brave');
                        }
                        break;
                    case UA_DEVICE:
                        // Chrome-specific detection: check for 'mobile' value of navigator.userAgentData
                        if (!this.get(TYPE) && NAVIGATOR_UADATA && NAVIGATOR_UADATA[MOBILE]) {
                            this.set(TYPE, MOBILE);
                        }
                        // iPadOS-specific detection: identified as Mac, but has some iOS-only properties
                        if (this.get(MODEL) == 'Macintosh' && NAVIGATOR && typeof NAVIGATOR.standalone !== UNDEF_TYPE && NAVIGATOR.maxTouchPoints && NAVIGATOR.maxTouchPoints > 2) {
                            this.set(MODEL, 'iPad')
                                .set(TYPE, TABLET);
                        }
                        break;
                    case UA_OS:
                        // Chrome-specific detection: check for 'platform' value of navigator.userAgentData
                        if (!this.get(NAME) && NAVIGATOR_UADATA && NAVIGATOR_UADATA[PLATFORM]) {
                            this.set(NAME, NAVIGATOR_UADATA[PLATFORM]);
                        }
                        break;
                    case UA_RESULT:
                        var data = this.data;
                        var detect = function (itemType) {
                            return data[itemType]
                                    .getItem()
                                    .detectFeature()
                                    .get();
                        };
                        this.set(UA_BROWSER, detect(UA_BROWSER))
                            .set(UA_CPU, detect(UA_CPU))
                            .set(UA_DEVICE, detect(UA_DEVICE))
                            .set(UA_ENGINE, detect(UA_ENGINE))
                            .set(UA_OS, detect(UA_OS));
                }
            }
            return this;
        };

        this.parseUA = function () {
            if (this.itemType != UA_RESULT) {
                rgxMapper.call(this.data, this.ua, this.rgxMap);
            }
            if (this.itemType == UA_BROWSER) {
                this.set(MAJOR, majorize(this.get(VERSION)));
            }
            return this;
        };

        this.parseCH = function () {
            var uaCH = this.uaCH,
                rgxMap = this.rgxMap;
    
            switch (this.itemType) {
                case UA_BROWSER:
                    var brands = uaCH[FULLVERLIST] || uaCH[BRANDS], prevName;
                    if (brands) {
                        for (var i in brands) {
                            var brandName = strip(/(Google|Microsoft) /, brands[i].brand || brands[i]),
                                brandVersion = brands[i].version;
                            if (!/not.a.brand/i.test(brandName) && (!prevName || (/chrom/i.test(prevName) && !/chromi/i.test(brandName)))) {
                                this.set(NAME, brandName)
                                    .set(VERSION, brandVersion)
                                    .set(MAJOR, majorize(brandVersion));
                                prevName = brandName;
                            }
                        }
                    }
                    break;
                case UA_CPU:
                    var archName = uaCH[ARCHITECTURE];
                    if (archName) {
                        if (archName && uaCH[BITNESS] == '64') archName += '64';
                        rgxMapper.call(this.data, archName + ';', rgxMap);
                    }
                    break;
                case UA_DEVICE:
                    if (uaCH[MOBILE]) {
                        this.set(TYPE, MOBILE);
                    }
                    if (uaCH[MODEL]) {
                        this.set(MODEL, uaCH[MODEL]);
                    }
                    // Xbox-Specific Detection
                    if (uaCH[MODEL] == 'Xbox') {
                        this.set(TYPE, CONSOLE)
                            .set(VENDOR, MICROSOFT);
                    }
                    if (uaCH[FORMFACTORS]) {
                        var ff;
                        if (typeof uaCH[FORMFACTORS] !== 'string') {
                            var idx = 0;
                            while (!ff && idx < uaCH[FORMFACTORS].length) {
                                ff = strMapper(uaCH[FORMFACTORS][idx++], formFactorsMap);
                            }
                        } else {
                            ff = strMapper(uaCH[FORMFACTORS], formFactorsMap);
                        }
                        this.set(TYPE, ff);
                    }
                    break;
                case UA_OS:
                    var osName = uaCH[PLATFORM];
                    if(osName) {
                        var osVersion = uaCH[PLATFORMVER];
                        if (osName == WINDOWS) osVersion = (parseInt(majorize(osVersion), 10) >= 13 ? '11' : '10');
                        this.set(NAME, osName)
                            .set(VERSION, osVersion);
                    }
                    // Xbox-Specific Detection
                    if (this.get(NAME) == WINDOWS && uaCH[MODEL] == 'Xbox') {
                        this.set(NAME, 'Xbox')
                            .set(VERSION, undefined);
                    }           
                    break;
                case UA_RESULT:
                    var data = this.data;
                    var parse = function (itemType) {
                        return data[itemType]
                                .getItem()
                                .setCH(uaCH)
                                .parseCH()
                                .get();
                    };
                    this.set(UA_BROWSER, parse(UA_BROWSER))
                        .set(UA_CPU, parse(UA_CPU))
                        .set(UA_DEVICE, parse(UA_DEVICE))
                        .set(UA_ENGINE, parse(UA_ENGINE))
                        .set(UA_OS, parse(UA_OS));
            }
            return this;
        };

        setProps.call(this, [
            ['itemType', itemType],
            ['ua', ua],
            ['uaCH', uaCH],
            ['rgxMap', rgxMap],
            ['data', createIData(this, itemType)]
        ]);

        return this;
    }

    function UAParser (ua, extensions, headers) {

        if (typeof ua === OBJ_TYPE) {
            if (isExtensions(ua, true)) {
                if (typeof extensions === OBJ_TYPE) {
                    headers = extensions;               // case UAParser(extensions, headers)           
                }
                extensions = ua;                        // case UAParser(extensions)
            } else {
                headers = ua;                           // case UAParser(headers)
                extensions = undefined;
            }
            ua = undefined;
        } else if (typeof ua === STR_TYPE && !isExtensions(extensions, true)) {
            headers = extensions;                       // case UAParser(ua, headers)
            extensions = undefined;
        }

        // Convert Headers object into a plain object
        if (headers && typeof headers.append === FUNC_TYPE) {
            var kv = {};
            headers.forEach(function (v, k) { kv[k] = v; });
            headers = kv;
        }
        
        if (!(this instanceof UAParser)) {
            return new UAParser(ua, extensions, headers).getResult();
        }

        var userAgent = typeof ua === STR_TYPE ? ua :                                       // Passed user-agent string
                                (headers && headers[USER_AGENT] ? headers[USER_AGENT] :     // User-Agent from passed headers
                                ((NAVIGATOR && NAVIGATOR.userAgent) ? NAVIGATOR.userAgent : // navigator.userAgent
                                    EMPTY)),                                                // empty string

            httpUACH = new UACHData(headers, true),
            regexMap = extensions ? 
                        extend(defaultRegexes, extensions) : 
                        defaultRegexes,

            createItemFunc = function (itemType) {
                if (itemType == UA_RESULT) {
                    return function () {
                        return new UAItem(itemType, userAgent, regexMap, httpUACH)
                                    .set('ua', userAgent)
                                    .set(UA_BROWSER, this.getBrowser())
                                    .set(UA_CPU, this.getCPU())
                                    .set(UA_DEVICE, this.getDevice())
                                    .set(UA_ENGINE, this.getEngine())
                                    .set(UA_OS, this.getOS())
                                    .get();
                    };
                } else {
                    return function () {
                        return new UAItem(itemType, userAgent, regexMap[itemType], httpUACH)
                                    .parseUA()
                                    .get();
                    };
                }
            };
            
        // public methods
        setProps.call(this, [
            ['getBrowser', createItemFunc(UA_BROWSER)],
            ['getCPU', createItemFunc(UA_CPU)],
            ['getDevice', createItemFunc(UA_DEVICE)],
            ['getEngine', createItemFunc(UA_ENGINE)],
            ['getOS', createItemFunc(UA_OS)],
            ['getResult', createItemFunc(UA_RESULT)],
            ['getUA', function () { return userAgent; }],
            ['setUA', function (ua) {
                if (isString(ua))
                    userAgent = ua.length > UA_MAX_LENGTH ? trim(ua, UA_MAX_LENGTH) : ua;
                return this;
            }]
        ])
        .setUA(userAgent);

        return this;
    }

    UAParser.VERSION = LIBVERSION;
    UAParser.BROWSER =  enumerize([NAME, VERSION, MAJOR, TYPE]);
    UAParser.CPU = enumerize([ARCHITECTURE]);
    UAParser.DEVICE = enumerize([MODEL, VENDOR, TYPE, CONSOLE, MOBILE, SMARTTV, TABLET, WEARABLE, EMBEDDED]);
    UAParser.ENGINE = UAParser.OS = enumerize([NAME, VERSION]);

    ///////////
    // Export
    //////////

    // check js environment
    if (typeof exports !== UNDEF_TYPE) {
        // nodejs env
        if ("object" !== UNDEF_TYPE && module.exports) {
            exports = module.exports = UAParser;
        }
        exports.UAParser = UAParser;
    } else {
        // requirejs env (optional)
        if ("function" === FUNC_TYPE && __webpack_require__.amdO) {
            !(__WEBPACK_AMD_DEFINE_RESULT__ = (function () {
                return UAParser;
            }).call(exports, __webpack_require__, exports, module),
		__WEBPACK_AMD_DEFINE_RESULT__ !== undefined && (module.exports = __WEBPACK_AMD_DEFINE_RESULT__));
        } else if (isWindow) {
            // browser env
            window.UAParser = UAParser;
        }
    }

    // jQuery/Zepto specific (optional)
    // Note:
    //   In AMD env the global scope should be kept clean, but jQuery is an exception.
    //   jQuery always exports to global scope, unless jQuery.noConflict(true) is used,
    //   and we should catch that.
    var $ = isWindow && (window.jQuery || window.Zepto);
    if ($ && !$.ua) {
        var parser = new UAParser();
        $.ua = parser.getResult();
        $.ua.get = function () {
            return parser.getUA();
        };
        $.ua.set = function (ua) {
            parser.setUA(ua);
            var result = parser.getResult();
            for (var prop in result) {
                $.ua[prop] = result[prop];
            }
        };
    }

})(typeof window === 'object' ? window : this);


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/amd options */
/******/ 	(() => {
/******/ 		__webpack_require__.amdO = {};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/global */
/******/ 	(() => {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/jsonp chunk loading */
/******/ 	(() => {
/******/ 		__webpack_require__.b = document.baseURI || self.location.href;
/******/ 		
/******/ 		// object to store loaded and loading chunks
/******/ 		// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 		// [resolve, reject, Promise] = chunk loading, 0 = chunk loaded
/******/ 		var installedChunks = {
/******/ 			476: 0,
/******/ 			570: 0
/******/ 		};
/******/ 		
/******/ 		// no chunk on demand loading
/******/ 		
/******/ 		// no prefetching
/******/ 		
/******/ 		// no preloaded
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 		
/******/ 		// no on chunks loaded
/******/ 		
/******/ 		// no jsonp function
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/nonce */
/******/ 	(() => {
/******/ 		__webpack_require__.nc = undefined;
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be in strict mode.
(() => {
"use strict";

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  "default": () => (/* binding */ main)
});

;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/typeof.js
function _typeof(obj) {
  "@babel/helpers - typeof";

  return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (obj) {
    return typeof obj;
  } : function (obj) {
    return obj && "function" == typeof Symbol && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj;
  }, _typeof(obj);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/regeneratorRuntime.js

function regeneratorRuntime_regeneratorRuntime() {
  "use strict"; /*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/facebook/regenerator/blob/main/LICENSE */
  regeneratorRuntime_regeneratorRuntime = function _regeneratorRuntime() {
    return exports;
  };
  var exports = {},
    Op = Object.prototype,
    hasOwn = Op.hasOwnProperty,
    defineProperty = Object.defineProperty || function (obj, key, desc) {
      obj[key] = desc.value;
    },
    $Symbol = "function" == typeof Symbol ? Symbol : {},
    iteratorSymbol = $Symbol.iterator || "@@iterator",
    asyncIteratorSymbol = $Symbol.asyncIterator || "@@asyncIterator",
    toStringTagSymbol = $Symbol.toStringTag || "@@toStringTag";
  function define(obj, key, value) {
    return Object.defineProperty(obj, key, {
      value: value,
      enumerable: !0,
      configurable: !0,
      writable: !0
    }), obj[key];
  }
  try {
    define({}, "");
  } catch (err) {
    define = function define(obj, key, value) {
      return obj[key] = value;
    };
  }
  function wrap(innerFn, outerFn, self, tryLocsList) {
    var protoGenerator = outerFn && outerFn.prototype instanceof Generator ? outerFn : Generator,
      generator = Object.create(protoGenerator.prototype),
      context = new Context(tryLocsList || []);
    return defineProperty(generator, "_invoke", {
      value: makeInvokeMethod(innerFn, self, context)
    }), generator;
  }
  function tryCatch(fn, obj, arg) {
    try {
      return {
        type: "normal",
        arg: fn.call(obj, arg)
      };
    } catch (err) {
      return {
        type: "throw",
        arg: err
      };
    }
  }
  exports.wrap = wrap;
  var ContinueSentinel = {};
  function Generator() {}
  function GeneratorFunction() {}
  function GeneratorFunctionPrototype() {}
  var IteratorPrototype = {};
  define(IteratorPrototype, iteratorSymbol, function () {
    return this;
  });
  var getProto = Object.getPrototypeOf,
    NativeIteratorPrototype = getProto && getProto(getProto(values([])));
  NativeIteratorPrototype && NativeIteratorPrototype !== Op && hasOwn.call(NativeIteratorPrototype, iteratorSymbol) && (IteratorPrototype = NativeIteratorPrototype);
  var Gp = GeneratorFunctionPrototype.prototype = Generator.prototype = Object.create(IteratorPrototype);
  function defineIteratorMethods(prototype) {
    ["next", "throw", "return"].forEach(function (method) {
      define(prototype, method, function (arg) {
        return this._invoke(method, arg);
      });
    });
  }
  function AsyncIterator(generator, PromiseImpl) {
    function invoke(method, arg, resolve, reject) {
      var record = tryCatch(generator[method], generator, arg);
      if ("throw" !== record.type) {
        var result = record.arg,
          value = result.value;
        return value && "object" == _typeof(value) && hasOwn.call(value, "__await") ? PromiseImpl.resolve(value.__await).then(function (value) {
          invoke("next", value, resolve, reject);
        }, function (err) {
          invoke("throw", err, resolve, reject);
        }) : PromiseImpl.resolve(value).then(function (unwrapped) {
          result.value = unwrapped, resolve(result);
        }, function (error) {
          return invoke("throw", error, resolve, reject);
        });
      }
      reject(record.arg);
    }
    var previousPromise;
    defineProperty(this, "_invoke", {
      value: function value(method, arg) {
        function callInvokeWithMethodAndArg() {
          return new PromiseImpl(function (resolve, reject) {
            invoke(method, arg, resolve, reject);
          });
        }
        return previousPromise = previousPromise ? previousPromise.then(callInvokeWithMethodAndArg, callInvokeWithMethodAndArg) : callInvokeWithMethodAndArg();
      }
    });
  }
  function makeInvokeMethod(innerFn, self, context) {
    var state = "suspendedStart";
    return function (method, arg) {
      if ("executing" === state) throw new Error("Generator is already running");
      if ("completed" === state) {
        if ("throw" === method) throw arg;
        return doneResult();
      }
      for (context.method = method, context.arg = arg;;) {
        var delegate = context.delegate;
        if (delegate) {
          var delegateResult = maybeInvokeDelegate(delegate, context);
          if (delegateResult) {
            if (delegateResult === ContinueSentinel) continue;
            return delegateResult;
          }
        }
        if ("next" === context.method) context.sent = context._sent = context.arg;else if ("throw" === context.method) {
          if ("suspendedStart" === state) throw state = "completed", context.arg;
          context.dispatchException(context.arg);
        } else "return" === context.method && context.abrupt("return", context.arg);
        state = "executing";
        var record = tryCatch(innerFn, self, context);
        if ("normal" === record.type) {
          if (state = context.done ? "completed" : "suspendedYield", record.arg === ContinueSentinel) continue;
          return {
            value: record.arg,
            done: context.done
          };
        }
        "throw" === record.type && (state = "completed", context.method = "throw", context.arg = record.arg);
      }
    };
  }
  function maybeInvokeDelegate(delegate, context) {
    var method = delegate.iterator[context.method];
    if (undefined === method) {
      if (context.delegate = null, "throw" === context.method) {
        if (delegate.iterator["return"] && (context.method = "return", context.arg = undefined, maybeInvokeDelegate(delegate, context), "throw" === context.method)) return ContinueSentinel;
        context.method = "throw", context.arg = new TypeError("The iterator does not provide a 'throw' method");
      }
      return ContinueSentinel;
    }
    var record = tryCatch(method, delegate.iterator, context.arg);
    if ("throw" === record.type) return context.method = "throw", context.arg = record.arg, context.delegate = null, ContinueSentinel;
    var info = record.arg;
    return info ? info.done ? (context[delegate.resultName] = info.value, context.next = delegate.nextLoc, "return" !== context.method && (context.method = "next", context.arg = undefined), context.delegate = null, ContinueSentinel) : info : (context.method = "throw", context.arg = new TypeError("iterator result is not an object"), context.delegate = null, ContinueSentinel);
  }
  function pushTryEntry(locs) {
    var entry = {
      tryLoc: locs[0]
    };
    1 in locs && (entry.catchLoc = locs[1]), 2 in locs && (entry.finallyLoc = locs[2], entry.afterLoc = locs[3]), this.tryEntries.push(entry);
  }
  function resetTryEntry(entry) {
    var record = entry.completion || {};
    record.type = "normal", delete record.arg, entry.completion = record;
  }
  function Context(tryLocsList) {
    this.tryEntries = [{
      tryLoc: "root"
    }], tryLocsList.forEach(pushTryEntry, this), this.reset(!0);
  }
  function values(iterable) {
    if (iterable) {
      var iteratorMethod = iterable[iteratorSymbol];
      if (iteratorMethod) return iteratorMethod.call(iterable);
      if ("function" == typeof iterable.next) return iterable;
      if (!isNaN(iterable.length)) {
        var i = -1,
          next = function next() {
            for (; ++i < iterable.length;) {
              if (hasOwn.call(iterable, i)) return next.value = iterable[i], next.done = !1, next;
            }
            return next.value = undefined, next.done = !0, next;
          };
        return next.next = next;
      }
    }
    return {
      next: doneResult
    };
  }
  function doneResult() {
    return {
      value: undefined,
      done: !0
    };
  }
  return GeneratorFunction.prototype = GeneratorFunctionPrototype, defineProperty(Gp, "constructor", {
    value: GeneratorFunctionPrototype,
    configurable: !0
  }), defineProperty(GeneratorFunctionPrototype, "constructor", {
    value: GeneratorFunction,
    configurable: !0
  }), GeneratorFunction.displayName = define(GeneratorFunctionPrototype, toStringTagSymbol, "GeneratorFunction"), exports.isGeneratorFunction = function (genFun) {
    var ctor = "function" == typeof genFun && genFun.constructor;
    return !!ctor && (ctor === GeneratorFunction || "GeneratorFunction" === (ctor.displayName || ctor.name));
  }, exports.mark = function (genFun) {
    return Object.setPrototypeOf ? Object.setPrototypeOf(genFun, GeneratorFunctionPrototype) : (genFun.__proto__ = GeneratorFunctionPrototype, define(genFun, toStringTagSymbol, "GeneratorFunction")), genFun.prototype = Object.create(Gp), genFun;
  }, exports.awrap = function (arg) {
    return {
      __await: arg
    };
  }, defineIteratorMethods(AsyncIterator.prototype), define(AsyncIterator.prototype, asyncIteratorSymbol, function () {
    return this;
  }), exports.AsyncIterator = AsyncIterator, exports.async = function (innerFn, outerFn, self, tryLocsList, PromiseImpl) {
    void 0 === PromiseImpl && (PromiseImpl = Promise);
    var iter = new AsyncIterator(wrap(innerFn, outerFn, self, tryLocsList), PromiseImpl);
    return exports.isGeneratorFunction(outerFn) ? iter : iter.next().then(function (result) {
      return result.done ? result.value : iter.next();
    });
  }, defineIteratorMethods(Gp), define(Gp, toStringTagSymbol, "Generator"), define(Gp, iteratorSymbol, function () {
    return this;
  }), define(Gp, "toString", function () {
    return "[object Generator]";
  }), exports.keys = function (val) {
    var object = Object(val),
      keys = [];
    for (var key in object) {
      keys.push(key);
    }
    return keys.reverse(), function next() {
      for (; keys.length;) {
        var key = keys.pop();
        if (key in object) return next.value = key, next.done = !1, next;
      }
      return next.done = !0, next;
    };
  }, exports.values = values, Context.prototype = {
    constructor: Context,
    reset: function reset(skipTempReset) {
      if (this.prev = 0, this.next = 0, this.sent = this._sent = undefined, this.done = !1, this.delegate = null, this.method = "next", this.arg = undefined, this.tryEntries.forEach(resetTryEntry), !skipTempReset) for (var name in this) {
        "t" === name.charAt(0) && hasOwn.call(this, name) && !isNaN(+name.slice(1)) && (this[name] = undefined);
      }
    },
    stop: function stop() {
      this.done = !0;
      var rootRecord = this.tryEntries[0].completion;
      if ("throw" === rootRecord.type) throw rootRecord.arg;
      return this.rval;
    },
    dispatchException: function dispatchException(exception) {
      if (this.done) throw exception;
      var context = this;
      function handle(loc, caught) {
        return record.type = "throw", record.arg = exception, context.next = loc, caught && (context.method = "next", context.arg = undefined), !!caught;
      }
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i],
          record = entry.completion;
        if ("root" === entry.tryLoc) return handle("end");
        if (entry.tryLoc <= this.prev) {
          var hasCatch = hasOwn.call(entry, "catchLoc"),
            hasFinally = hasOwn.call(entry, "finallyLoc");
          if (hasCatch && hasFinally) {
            if (this.prev < entry.catchLoc) return handle(entry.catchLoc, !0);
            if (this.prev < entry.finallyLoc) return handle(entry.finallyLoc);
          } else if (hasCatch) {
            if (this.prev < entry.catchLoc) return handle(entry.catchLoc, !0);
          } else {
            if (!hasFinally) throw new Error("try statement without catch or finally");
            if (this.prev < entry.finallyLoc) return handle(entry.finallyLoc);
          }
        }
      }
    },
    abrupt: function abrupt(type, arg) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.tryLoc <= this.prev && hasOwn.call(entry, "finallyLoc") && this.prev < entry.finallyLoc) {
          var finallyEntry = entry;
          break;
        }
      }
      finallyEntry && ("break" === type || "continue" === type) && finallyEntry.tryLoc <= arg && arg <= finallyEntry.finallyLoc && (finallyEntry = null);
      var record = finallyEntry ? finallyEntry.completion : {};
      return record.type = type, record.arg = arg, finallyEntry ? (this.method = "next", this.next = finallyEntry.finallyLoc, ContinueSentinel) : this.complete(record);
    },
    complete: function complete(record, afterLoc) {
      if ("throw" === record.type) throw record.arg;
      return "break" === record.type || "continue" === record.type ? this.next = record.arg : "return" === record.type ? (this.rval = this.arg = record.arg, this.method = "return", this.next = "end") : "normal" === record.type && afterLoc && (this.next = afterLoc), ContinueSentinel;
    },
    finish: function finish(finallyLoc) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.finallyLoc === finallyLoc) return this.complete(entry.completion, entry.afterLoc), resetTryEntry(entry), ContinueSentinel;
      }
    },
    "catch": function _catch(tryLoc) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.tryLoc === tryLoc) {
          var record = entry.completion;
          if ("throw" === record.type) {
            var thrown = record.arg;
            resetTryEntry(entry);
          }
          return thrown;
        }
      }
      throw new Error("illegal catch attempt");
    },
    delegateYield: function delegateYield(iterable, resultName, nextLoc) {
      return this.delegate = {
        iterator: values(iterable),
        resultName: resultName,
        nextLoc: nextLoc
      }, "next" === this.method && (this.arg = undefined), ContinueSentinel;
    }
  }, exports;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/defineProperty.js
function _defineProperty(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }
  return obj;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/objectSpread2.js

function ownKeys(object, enumerableOnly) {
  var keys = Object.keys(object);
  if (Object.getOwnPropertySymbols) {
    var symbols = Object.getOwnPropertySymbols(object);
    enumerableOnly && (symbols = symbols.filter(function (sym) {
      return Object.getOwnPropertyDescriptor(object, sym).enumerable;
    })), keys.push.apply(keys, symbols);
  }
  return keys;
}
function _objectSpread2(target) {
  for (var i = 1; i < arguments.length; i++) {
    var source = null != arguments[i] ? arguments[i] : {};
    i % 2 ? ownKeys(Object(source), !0).forEach(function (key) {
      _defineProperty(target, key, source[key]);
    }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)) : ownKeys(Object(source)).forEach(function (key) {
      Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key));
    });
  }
  return target;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/objectWithoutPropertiesLoose.js
function _objectWithoutPropertiesLoose(source, excluded) {
  if (source == null) return {};
  var target = {};
  var sourceKeys = Object.keys(source);
  var key, i;
  for (i = 0; i < sourceKeys.length; i++) {
    key = sourceKeys[i];
    if (excluded.indexOf(key) >= 0) continue;
    target[key] = source[key];
  }
  return target;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/objectWithoutProperties.js

function _objectWithoutProperties(source, excluded) {
  if (source == null) return {};
  var target = _objectWithoutPropertiesLoose(source, excluded);
  var key, i;
  if (Object.getOwnPropertySymbols) {
    var sourceSymbolKeys = Object.getOwnPropertySymbols(source);
    for (i = 0; i < sourceSymbolKeys.length; i++) {
      key = sourceSymbolKeys[i];
      if (excluded.indexOf(key) >= 0) continue;
      if (!Object.prototype.propertyIsEnumerable.call(source, key)) continue;
      target[key] = source[key];
    }
  }
  return target;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/asyncToGenerator.js
function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) {
  try {
    var info = gen[key](arg);
    var value = info.value;
  } catch (error) {
    reject(error);
    return;
  }
  if (info.done) {
    resolve(value);
  } else {
    Promise.resolve(value).then(_next, _throw);
  }
}
function asyncToGenerator_asyncToGenerator(fn) {
  return function () {
    var self = this,
      args = arguments;
    return new Promise(function (resolve, reject) {
      var gen = fn.apply(self, args);
      function _next(value) {
        asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value);
      }
      function _throw(err) {
        asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err);
      }
      _next(undefined);
    });
  };
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/arrayWithHoles.js
function _arrayWithHoles(arr) {
  if (Array.isArray(arr)) return arr;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/iterableToArrayLimit.js
function _iterableToArrayLimit(arr, i) {
  var _i = arr == null ? null : typeof Symbol !== "undefined" && arr[Symbol.iterator] || arr["@@iterator"];
  if (_i == null) return;
  var _arr = [];
  var _n = true;
  var _d = false;
  var _s, _e;
  try {
    for (_i = _i.call(arr); !(_n = (_s = _i.next()).done); _n = true) {
      _arr.push(_s.value);
      if (i && _arr.length === i) break;
    }
  } catch (err) {
    _d = true;
    _e = err;
  } finally {
    try {
      if (!_n && _i["return"] != null) _i["return"]();
    } finally {
      if (_d) throw _e;
    }
  }
  return _arr;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/arrayLikeToArray.js
function _arrayLikeToArray(arr, len) {
  if (len == null || len > arr.length) len = arr.length;
  for (var i = 0, arr2 = new Array(len); i < len; i++) {
    arr2[i] = arr[i];
  }
  return arr2;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/unsupportedIterableToArray.js

function _unsupportedIterableToArray(o, minLen) {
  if (!o) return;
  if (typeof o === "string") return _arrayLikeToArray(o, minLen);
  var n = Object.prototype.toString.call(o).slice(8, -1);
  if (n === "Object" && o.constructor) n = o.constructor.name;
  if (n === "Map" || n === "Set") return Array.from(o);
  if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/nonIterableRest.js
function _nonIterableRest() {
  throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/slicedToArray.js




function _slicedToArray(arr, i) {
  return _arrayWithHoles(arr) || _iterableToArrayLimit(arr, i) || _unsupportedIterableToArray(arr, i) || _nonIterableRest();
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/arrayWithoutHoles.js

function _arrayWithoutHoles(arr) {
  if (Array.isArray(arr)) return _arrayLikeToArray(arr);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/iterableToArray.js
function _iterableToArray(iter) {
  if (typeof Symbol !== "undefined" && iter[Symbol.iterator] != null || iter["@@iterator"] != null) return Array.from(iter);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/nonIterableSpread.js
function _nonIterableSpread() {
  throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/toConsumableArray.js




function _toConsumableArray(arr) {
  return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _unsupportedIterableToArray(arr) || _nonIterableSpread();
}
;// CONCATENATED MODULE: ./src/sdk/constants.js
var SECOND = 1000;
var MINUTE = SECOND * 60;
var HOUR = MINUTE * 60;
var DAY = HOUR * 24;
var REASON_GENERAL = 'general';
var REASON_GDPR = 'gdpr';
var HTTP_ERRORS = {
  'TRANSACTION_ERROR': 'XHR transaction failed due to an error',
  'SERVER_MALFORMED_RESPONSE': 'Response from server is malformed',
  'SERVER_INTERNAL_ERROR': 'Internal error occurred on the server',
  'SERVER_CANNOT_PROCESS': 'Server was not able to process the request, probably due to error coming from the client',
  'NO_CONNECTION': 'No internet connectivity',
  'SKIP': 'Skipping slower attempt',
  'MISSING_URL': 'Url is not provided'
};
var STORAGE_TYPES = {
  NO_STORAGE: 'noStorage',
  INDEXED_DB: 'indexedDB',
  LOCAL_STORAGE: 'localStorage'
};
var ENDPOINTS = {
  default: {
    endpointName: 'Default',
    app: 'https://65d9569300f3418494c47d063d55011f.api.mockbin.io/',
    gdpr: 'https://gdpr.wisetrack.com'
  },
  india: {
    endpointName: 'Indian',
    app: 'https://app.wisetrack.net.in',
    gdpr: 'https://gdpr.wisetrack.net.in'
  },
  china: {
    endpointName: 'Chinese',
    app: 'https://app.wisetrack.world',
    gdpr: 'https://gdpr.wisetrack.world'
  },
  EU: {
    endpointName: 'EU',
    app: 'https://app.eu.wisetrack.com',
    gdpr: 'https://gdpr.eu.wisetrack.com'
  },
  TR: {
    endpointName: 'TR',
    app: 'https://app.tr.wisetrack.com',
    gdpr: 'https://gdpr.tr.wisetrack.com'
  },
  US: {
    endpointName: 'US',
    app: 'https://app.us.wisetrack.com',
    gdpr: 'https://gdpr.us.wisetrack.com'
  }
};
;// CONCATENATED MODULE: ./src/sdk/utilities.ts




/**
 * Build human readable list
 */
function buildList(array /*: Array<unknown>*/) /*: string*/{
  if (!array.length) {
    return '';
  }
  if (array.length === 1) {
    return "".concat(array[0]);
  }
  var lastIndex = array.length - 1;
  var firstPart = array.slice(0, lastIndex).join(', ');
  return "".concat(firstPart, " and ").concat(array[lastIndex]);
}

/**
 * Check if object is empty
 */
function isEmpty(obj /*: Record<string, unknown>*/) /*: boolean*/{
  return !Object.keys(obj).length && obj.constructor === Object;
}

/**
 * Check if value is object
 */
function isObject(obj /*: any*/) /*: boolean*/{
  // eslint-disable-line @typescript-eslint/no-explicit-any
  return _typeof(obj) === 'object' && obj !== null && !(obj instanceof Array);
}

/**
 * Check if string is valid json
 */
function isValidJson(string /*: string*/) /*: boolean*/{
  try {
    var json = JSON.parse(string);
    return isObject(json);
  } catch (e) {
    return false;
  }
}

/**
 * Find index of an element in the list and return it
 */
function findIndex /*:: <K extends string, T extends Record<K, unknown>>*/(array /*: Array<T>*/, key /*: K | Array<K>*/, target /*: T*/) /*: number*/{
  function isEqual(item /*: T*/) {
    return Array.isArray(key) ? key.every(function (k) {
      return item[k] === target[k];
    }) : item[key] === target;
  }
  for (var i = 0; i < array.length; i += 1) {
    if (isEqual(array[i])) {
      return i;
    }
  }
  return -1;
}

/**
 * Convert array with key/value item structure into key/value pairs object
 */
function convertToMap /*:: <T>*/() /*: Record<string, T>*/{
  var array /*: Array<{ key: string, value: T }>*/ = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [];
  return array.reduce(function (acc, o) {
    return _objectSpread2(_objectSpread2({}, acc), {}, _defineProperty({}, o.key, o.value));
  }, {});
}

/**
 * Find intersecting values of provided array against given values
 */
function intersection /*:: <T>*/() /*: Array<T>*/{
  var array /*: Array<T>*/ = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [];
  var values /*: Array<T>*/ = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : [];
  return array.filter(function (item) {
    return values.indexOf(item) !== -1;
  });
}

/**
 * Check if particular url is a certain request
 */
function isRequest(url /*: string*/, requestName /*: string*/) /*: boolean*/{
  var regex = new RegExp("\\/".concat(requestName, "(\\/.*|\\?.*){0,1}$"));
  console.log("_Trace  regex.test:".concat(regex.test(url)));
  return regex.test(url);
}
function isRequestSession(url /*: string*/, requestName /*: string*/) /*: boolean*/{
  if (url.toLowerCase().includes('session'.toLowerCase())) {
    return true;
  } else {
    return false;
  }
}
function isRequestEvent(url /*: string*/, requestName /*: string*/) /*: boolean*/{
  if (url.toLowerCase().includes('event'.toLowerCase())) {
    return true;
  } else {
    return false;
  }
}

/**
 * Extract the host name for the url
 */
function getHostName() /*: string*/{
  var url = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
  return url.replace(/^(http(s)*:\/\/)*(www\.)*/, '').split('/')[0].split('?')[0];
}

/**
 * Transform array entry into object key:value pair entry
 */
function reducer /*:: <K extends string, T>*/(acc /*: Record<K, T>*/, _ref /*:: */) /*: Record<K, T>*/{
  var _ref2 = _slicedToArray(_ref /*:: */, 2),
    key = _ref2[0],
    value = _ref2[1];
  return _objectSpread2(_objectSpread2({}, acc), {}, _defineProperty({}, key, value));
}

/**
 * Extracts object entries in the [key, value] format
 */
function entries /*:: <K extends string, T>*/(object /*: Record<K, T>*/) /*: Array<[K, T]>*/{
  return Object.keys(object).map(function (key /*: K*/) {
    return [key, object[key]];
  });
}

/**
 * Extracts object values
 */
function values /*:: <T>*/(object /*: Record<string, T>*/) /*: Array<T>*/{
  return Object.keys(object).map(function (key /*: string*/) {
    return object[key];
  });
}

/**
 * Check if value is empty in any way (empty object, false value, zero) and use it as predicate method
 */
function isEmptyEntry(value /*: any*/) /*: boolean*/{
  // eslint-disable-line @typescript-eslint/no-explicit-any
  if (isObject(value)) {
    return !isEmpty(value);
  }
  return !!value || value === 0;
}
function isLocalStorageSupported() /*: boolean*/{
  try {
    var uid = new Date().toString();
    var storage = window.localStorage;
    storage.setItem(uid, uid);
    var result = storage.getItem(uid) === uid;
    storage.removeItem(uid);
    var support = !!(result && storage);
    return support;
  } catch (e) {
    return false;
  }
}

;// CONCATENATED MODULE: ./src/sdk/globals.js
/*:: declare var __WISETRACK__NAMESPACE: string*/
/*:: declare var __WISETRACK__SDK_VERSION: string*/
/*:: declare var process: {|
  env: {|
    NODE_ENV: 'development' | 'production' | 'test'
  |}
|}*/
var Globals = {
  namespace: "wisetrack-sdk" || 0,
  version: "0.9.0-alpha" || 0,
  env: "production"
};
/* harmony default export */ const globals = (Globals);
;// CONCATENATED MODULE: ./src/sdk/logger.js

var _levels2;


/*:: import { type LogOptionsT } from './types';*/
/*:: type LogLevelT = $PropertyType<LogOptionsT, 'logLevel'>*/
/*:: type MethodNameT = 'log' | 'info' | 'error' | 'warn'*/
var LEVEL_NONE = 'none';
var LEVEL_ERROR = 'error';
var LEVEL_WARNING = 'warning';
var LEVEL_INFO = 'info';
var LEVEL_VERBOSE = 'verbose';

/**
 * Logger levels
 * - none -> nothing is printed to the console
 * - error -> prints only error
 * - info -> prints info and error
 * - verbose -> prints log, info and error
 *
 * @type {Object}
 * @private
 */
var _levels = (_levels2 = {}, _defineProperty(_levels2, LEVEL_NONE, -1), _defineProperty(_levels2, LEVEL_ERROR, 0), _defineProperty(_levels2, LEVEL_WARNING, 1), _defineProperty(_levels2, LEVEL_INFO, 2), _defineProperty(_levels2, LEVEL_VERBOSE, 3), _levels2);

/**
 * Spaces placed after log level tag in console to align messages.
 *
 * @type {Object}
 * @private
 */
var _spaces = {
  'log': '  ',
  'info': ' ',
  'warn': ' ',
  'error': ''
};

/**
 * Default logger level per environment
 *
 * @type {Object}
 * @private
 */
var _envLogLevels = {
  development: LEVEL_VERBOSE,
  production: LEVEL_ERROR,
  test: LEVEL_VERBOSE
};

/**
 * Current logger level
 */
var _level = _getDefaultLogLevel();

/**
 * Optional output container to display logs for easier debugging
 *
 * @type {string}
 * @private
 */
var _output = '';

/**
 * Get default logger error per environment and fallback to error level when unknown env
 *
 * @returns {string}
 * @private
 */
function _getDefaultLogLevel() /*: LogLevelT*/{
  return _envLogLevels[globals.env] || LEVEL_ERROR;
}

/**
 * Set logger level, fallback to default log level
 *
 * @param {string=} logLevel
 * @param {string=} logOutput
 */
function setLogLevel(logLevel /*: LogLevelT*/, logOutput /*: string*/) /*: void*/{
  var exists = !logLevel || Object.keys(_levels).indexOf(logLevel) !== -1;
  if (!exists) {
    _log('error', 'error', 'You must set one of the available log levels: verbose, info, warning, error or none');
    return;
  }
  _level = logLevel || _getDefaultLogLevel();
  _output = logOutput || _output;
  _log('info', logLevel, "Log level set to ".concat(_level));
}

/**
 * Output the message to the console
 *
 * @param {string} methodName
 * @param {string} logLevel
 * @param {Array} args
 * @private
 */
function _log(methodName /*: MethodNameT*/, logLevel /*: LogLevelT*/) /*: void*/{
  var _console;
  if (_levels[_level] < _levels[logLevel]) {
    return;
  }
  var time = new Date().toISOString();
  var spaces = _spaces[methodName];
  var messagePrefix = ["[".concat(globals.namespace, "]"), time, "".concat(methodName.toUpperCase(), ":").concat(spaces)];
  var outputContainer = _output ? document.querySelector(_output) : null;
  for (var _len = arguments.length, args = new Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) {
    args[_key - 2] = arguments[_key];
  }
  (_console = console)[methodName].apply(_console, messagePrefix.concat(args)); // eslint-disable-line

  if (outputContainer) {
    outputContainer.textContent += "".concat(messagePrefix.join(' '), " ").concat(args.map(function (m) {
      return isObject(m) ? JSON.stringify(m) : m;
    }).join(' '), "\n");
    outputContainer.scrollTop = outputContainer.scrollHeight;
  }
}

/**
 * Apply predefined log level and return log method
 *
 * @param {string} name
 * @param {string} logLevel
 * @returns {Function: (Array) => void}
 * @private
 */
function _applyLevel(name /*: MethodNameT*/, logLevel /*: LogLevelT*/) {
  return function () {
    for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
      args[_key2] = arguments[_key2];
    }
    _log.apply(void 0, [name, logLevel].concat(args));
  };
}
var Logger = {
  setLogLevel: setLogLevel,
  log: _applyLevel('log', LEVEL_VERBOSE),
  info: _applyLevel('info', LEVEL_INFO),
  warn: _applyLevel('warn', LEVEL_WARNING),
  error: _applyLevel('error', LEVEL_ERROR)
};
/* harmony default export */ const sdk_logger = (Logger);
;// CONCATENATED MODULE: ./src/sdk/config.js



/*:: // 
import { type BaseParamsT, type CustomConfigT, type InitOptionsT, type BaseParamsListT, type BaseParamsMandatoryListT, type CustomConfigListT } from './types';*/




/**
 * Base parameters set by client
 * - app token
 * - environment
 * - default tracker
 * - external device ID
 *
 * @type {Object}
 * @private
 */
var _baseParams /*: BaseParamsT*/ = {};

/**
 * Custom config set by client
 * - url override
 * - event deduplication list limit
 *
 * @type {Object}
 * @private
 */
var _customConfig /*: CustomConfigT*/ = {};

/**
 * Mandatory fields to set for sdk initialization
 *
 * @type {string[]}
 * @private
 */
var _mandatory /*: BaseParamsMandatoryListT*/ = ['appToken', 'environment'];

/**
 * Allowed params to be sent with each request
 *
 * @type {string[]}
 * @private
 */
var _allowedParams /*: BaseParamsListT*/ = [].concat(_mandatory, ['defaultTracker', 'externalDeviceId']);

/**
 * Allowed configuration overrides
 *
 * @type {string[]}
 * @private
 */
var _allowedConfig /*: CustomConfigListT*/ = ['customUrl', 'dataResidency', 'urlStrategy', 'eventDeduplicationListLimit', 'namespace'];

/**
 * Global configuration object used across the sdk
 *
 * @type {{
 * namespace: string,
 * version: string,
 * sessionWindow: number,
 * sessionTimerWindow: number,
 * requestValidityWindow: number
 * }}
 */
var _baseConfig = {
  sessionWindow: 30 * MINUTE,
  sessionTimerWindow: 60 * SECOND,
  requestValidityWindow: 28 * DAY
};

/**
 * Check of configuration has been initialized
 *
 * @returns {boolean}
 */
function isInitialised() /*: boolean*/{
  return _mandatory.reduce(function (acc, key) {
    return acc && !!_baseParams[key];
  }, true);
}

/**
 * Get base params set by client
 *
 * @returns {Object}
 */
function getBaseParams() /*: BaseParamsT*/{
  return _objectSpread2({}, _baseParams);
}

/**
 * Set base params and custom config for the sdk to run
 *
 * @param {Object} options
 */
function set(options /*: InitOptionsT*/) /*: void*/{
  if (hasMissing(options)) {
    return;
  }
  var filteredParams = [].concat(_toConsumableArray(_allowedParams), _allowedConfig).filter(function (key) {
    return !!options[key];
  }).map(function (key) {
    return [key, options[key]];
  });
  _baseParams = filteredParams.filter(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 1),
      key = _ref2[0];
    return _allowedParams.indexOf(key) !== -1;
  }).reduce(reducer, {});
  _customConfig = filteredParams.filter(function (_ref3) {
    var _ref4 = _slicedToArray(_ref3, 1),
      key = _ref4[0];
    return _allowedConfig.indexOf(key) !== -1;
  }).reduce(reducer, {});
}

/**
 * Get custom config set by client
 *
 * @returns {Object}
 */
function getCustomConfig() /*: CustomConfigT*/{
  return _objectSpread2({}, _customConfig);
}

/**
 * Check if there are  missing mandatory parameters
 *
 * @param {Object} params
 * @returns {boolean}
 * @private
 */
function hasMissing(params /*: BaseParamsT*/) /*: boolean*/{
  var missing = _mandatory.filter(function (value) {
    return !params[value];
  });
  if (missing.length) {
    sdk_logger.error("You must define ".concat(buildList(missing)));
    return true;
  }
  return false;
}

/**
 * Restore config to its default state
 */
function destroy() /*: void*/{
  _baseParams = {};
  _customConfig = {};
}
var Config = _objectSpread2(_objectSpread2({}, _baseConfig), {}, {
  set: set,
  getBaseParams: getBaseParams,
  getCustomConfig: getCustomConfig,
  isInitialised: isInitialised,
  hasMissing: hasMissing,
  destroy: destroy
});
/* harmony default export */ const config = (Config);
;// CONCATENATED MODULE: ./src/sdk/storage/scheme.ts

var _values2;

var StoreName;
(function (StoreName) {
  StoreName["Queue"] = "queue";
  StoreName["ActivityState"] = "activityState";
  StoreName["GlobalParams"] = "globalParams";
  StoreName["EventDeduplication"] = "eventDeduplication";
})(StoreName || (StoreName = {}));
var PreferencesStoreName;
(function (PreferencesStoreName) {
  PreferencesStoreName["Preferences"] = "preferences";
})(PreferencesStoreName || (PreferencesStoreName = {}));
var ShortStoreName;
(function (ShortStoreName) {
  ShortStoreName["Queue"] = "q";
  ShortStoreName["ActivityState"] = "as";
  ShortStoreName["GlobalParams"] = "gp";
  ShortStoreName["EventDeduplication"] = "ed";
})(ShortStoreName || (ShortStoreName = {}));
var ShortPreferencesStoreName;
(function (ShortPreferencesStoreName) {
  ShortPreferencesStoreName["Preferences"] = "p";
})(ShortPreferencesStoreName || (ShortPreferencesStoreName = {}));
var _queueScheme /*: StoreOptions*/ = {
  keyPath: 'timestamp',
  autoIncrement: false,
  fields: {
    url: {
      key: 'u',
      values: {
        '/session': 1,
        '/event': 2,
        '/gdpr_forget_device': 3,
        '/sdk_click': 4,
        '/disable_third_party_sharing': 5
      }
    },
    method: {
      key: 'm',
      values: {
        GET: 1,
        POST: 2,
        PUT: 3,
        DELETE: 4
      }
    },
    timestamp: 't',
    createdAt: 'ca',
    params: {
      key: 'p',
      keys: {
        timeSpent: 'ts',
        sessionLength: 'sl',
        sessionCount: 'sc',
        eventCount: 'ec',
        lastInterval: 'li',
        eventToken: 'et',
        revenue: 're',
        currency: 'cu',
        callbackParams: 'cp',
        partnerParams: 'pp'
      }
    }
  }
};
var _activityStateScheme /*: StoreOptions*/ = {
  keyPath: 'uuid',
  autoIncrement: false,
  fields: {
    uuid: {
      key: 'u',
      values: {
        unknown: '-'
      }
    },
    timeSpent: 'ts',
    sessionLength: 'sl',
    sessionCount: 'sc',
    eventCount: 'ec',
    lastActive: 'la',
    lastInterval: 'li',
    installed: {
      key: 'in',
      values: {
        false: 0,
        true: 1
      }
    },
    attribution: {
      key: 'at',
      keys: {
        adid: 'a',
        tracker_token: 'tt',
        tracker_name: 'tn',
        network: 'nt',
        campaign: 'cm',
        adgroup: 'ag',
        creative: 'cr',
        click_label: 'cl',
        state: {
          key: 'st',
          values: {
            installed: 1,
            reattributed: 2
          }
        }
      }
    }
  }
};
var _globalParamsScheme /*: StoreOptions*/ = {
  keyPath: 'keyType',
  autoIncrement: false,
  index: 'type',
  fields: {
    keyType: {
      key: 'kt',
      composite: ['key', 'type']
    },
    key: 'k',
    value: 'v',
    type: {
      key: 't',
      values: {
        callback: 1,
        partner: 2
      }
    }
  }
};
var _eventDeduplicationScheme /*: StoreOptions*/ = {
  keyPath: 'internalId',
  autoIncrement: true,
  fields: {
    internalId: 'ii',
    id: 'i'
  }
};
var _preferencesScheme /*: StoreOptionsOptionalKey*/ = {
  fields: {
    thirdPartySharingDisabled: {
      key: 'td',
      keys: {
        reason: {
          key: 'r',
          values: _defineProperty({}, REASON_GENERAL, 1)
        },
        pending: {
          key: 'p',
          values: {
            false: 0,
            true: 1
          }
        }
      }
    },
    sdkDisabled: {
      key: 'sd',
      keys: {
        reason: {
          key: 'r',
          values: (_values2 = {}, _defineProperty(_values2, REASON_GENERAL, 1), _defineProperty(_values2, REASON_GDPR, 2), _values2)
        },
        pending: {
          key: 'p',
          values: {
            false: 0,
            true: 1
          }
        }
      }
    }
  }
};
var scheme /*: Scheme*/ = {
  queue: {
    name: ShortStoreName.Queue,
    scheme: _queueScheme
  },
  activityState: {
    name: ShortStoreName.ActivityState,
    scheme: _activityStateScheme
  },
  globalParams: {
    name: ShortStoreName.GlobalParams,
    scheme: _globalParamsScheme
  },
  eventDeduplication: {
    name: ShortStoreName.EventDeduplication,
    scheme: _eventDeduplicationScheme
  },
  preferences: {
    name: ShortPreferencesStoreName.Preferences,
    scheme: _preferencesScheme,
    permanent: true
  }
};
function isPredefinedValuesField(field /*: Maybe<StoreFieldScheme>*/) /*: field is StoreFieldPredefinedValues*/{
  return !!field && Object.prototype.hasOwnProperty.call(field, 'values');
}
function isNestingStoreField(field /*: Maybe<StoreFieldScheme>*/) /*: field is StoreFieldNestingFields*/{
  return !!field && Object.prototype.hasOwnProperty.call(field, 'keys');
}
function isCompositeKeyStoreField(field /*: Maybe<StoreFieldScheme>*/) /*: field is StoreFieldCompositeKey*/{
  return !!field && Object.prototype.hasOwnProperty.call(field, 'composite');
}
function isComplexStoreField(field /*: Maybe<StoreFieldScheme>*/) /*: field is StoreFieldComplex*/{
  return !!field && typeof field !== 'string';
}

/* harmony default export */ const storage_scheme = (scheme);
;// CONCATENATED MODULE: ./src/sdk/storage/scheme-map.ts




/**
 * Cast value into it's original type
 */
function _parseValue(value /*: string*/) /*: any*/{
  // eslint-disable-line @typescript-eslint/no-explicit-any
  try {
    return JSON.parse(value);
  } catch (e) {
    return value;
  }
}

/**
 * Flip key/value pairs
 */
function _flipObject(obj /*: Record<string, unknown>*/) /*: Record<string, unknown>*/{
  return entries(obj).map(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 2),
      key = _ref2[0],
      value = _ref2[1];
    return [value, _parseValue(key)];
  }).reduce(reducer, {});
}

/**
 * Flip store name definition names:
 * - short key pointing the long one along with additional configuration
 */
function _flipStoreNames(obj /*: StoresConfigurationMap*/) /*: StoresConfigurationMapFlipped*/{
  var flippedConfigs /*: Array<[ShortStoreNames, StoreConfigurationFlipped]>*/ = entries(obj).map(function (_ref3 /*:: */) {
    var _ref4 = _slicedToArray(_ref3 /*:: */, 2),
      name = _ref4[0],
      options = _ref4[1];
    var config = {
      name: name,
      permanent: options.permanent
    };
    return [options.name, config];
  });
  return flippedConfigs.reduce(reducer, {});
}

/**
 * Flip store scheme values
 */
function _flipStoreScheme(storeName /*: StoreNames*/, key /*: string*/, scheme /*: StoreFieldScheme*/) {
  var values = isPredefinedValuesField(scheme) ? {
    values: _flipObject(scheme.values)
  } : {};
  var keys = isNestingStoreField(scheme) ? {
    keys: _flipScheme(storeName, scheme.keys)
  } : {};
  var composite = isCompositeKeyStoreField(scheme) ? {
    composite: scheme.composite.map(function (key) {
      return _getShortKey(storeName, key);
    })
  } : {};
  return _objectSpread2(_objectSpread2(_objectSpread2({
    key: key
  }, values), keys), composite);
}

/**
 * Flip general scheme recursivelly
 */
function _flipScheme(storeName /*: StoreNames*/, fieldsScheme /*: StoreFields*/) {
  return entries(fieldsScheme).map(function (_ref5 /*:: */) {
    var _ref6 = _slicedToArray(_ref5 /*:: */, 2),
      key = _ref6[0],
      scheme = _ref6[1];
    return isComplexStoreField(scheme) ? [scheme.key, _flipStoreScheme(storeName, key, scheme)] : [scheme, key];
  }).reduce(reducer, {});
}

/**
 * Extend base scheme with some more maps for encoding
 */
function _prepareLeft() /*: StoreScheme*/{
  var storesOptions /*: Array<[StoreNames, StoreOptionsOptionalKey]>*/ = entries(storage_scheme).map(function (_ref7 /*:: */) {
    var _ref8 = _slicedToArray(_ref7 /*:: */, 2),
      storeName = _ref8[0],
      store = _ref8[1];
    var options /*: StoreOptionsOptionalKey*/ = {
      keyPath: store.scheme.keyPath,
      autoIncrement: store.scheme.autoIncrement,
      index: store.scheme.index,
      fields: store.scheme.fields
    };
    return [storeName, options];
  });
  return storesOptions.reduce(reducer, {});
}

/**
 * Prepare scheme for decoding
 */
function _prepareRight() /*: StoreScheme*/{
  var storesOptionsEncoded /*: Array<[StoreNames, StoreOptionsOptionalKey]>*/ = entries(Left).map(function (_ref9) {
    var _ref10 = _slicedToArray(_ref9, 2),
      storeName = _ref10[0],
      storeScheme = _ref10[1];
    var options /*: StoreOptionsOptionalKey*/ = {
      keyPath: _getShortKey(storeName, storeScheme.keyPath),
      autoIncrement: storeScheme.autoIncrement,
      index: _getShortKey(storeName, storeScheme.index),
      fields: _flipScheme(storeName, storeScheme.fields)
    };
    return [storeName, options];
  });
  return storesOptionsEncoded.reduce(reducer, {});
}

/**
 * Get available values for encoding
 */
function _getValuesMap() /*: Record<string, number>*/{
  // all pairs of predefined keys and values such as {GET: 1}
  return entries(storage_scheme).reduce(function (acc, _ref11) {
    var _ref12 = _slicedToArray(_ref11, 2),
      store = _ref12[1];
    return acc.concat(store.scheme.fields);
  }, []).map(function (scheme) {
    return values(scheme).filter(isPredefinedValuesField).map(function (map) {
      return entries(map.values);
    }).reduce(function (acc, map) {
      return acc.concat(map);
    }, []);
  }).reduce(function (acc, map) {
    return acc.concat(map);
  }, []).reduce(reducer, {});
}

/**
 * Get short key version of a specified key
 */
function _getShortKey(storeName /*: StoreNames*/, key /*: Maybe<string>*/) /*: Maybe<string>*/{
  if (!key) {
    return undefined;
  }
  var map = storage_scheme[storeName].scheme.fields[key];
  if (isComplexStoreField(map)) {
    return map.key;
  }
  return map || key;
}

/**
 * Get store names and their general configuration (if store is permanent or not)
 */
function _getStoreNames() /*: StoresConfigurationMap*/{
  var storeNames /*: Array<[StoreNames, StoreConfiguration]>*/ = entries(storage_scheme).map(function (_ref13) {
    var _ref14 = _slicedToArray(_ref13, 2),
      name = _ref14[0],
      store = _ref14[1];
    var config = {
      name: store.name,
      permanent: store.permanent
    };
    return [name, config];
  });
  return storeNames.reduce(reducer, {});
}
var Left = _prepareLeft();
var Right = _prepareRight();
var Values = _getValuesMap();
var StoreNamesAndConfigs = _getStoreNames();
/* harmony default export */ const scheme_map = ({
  left: Left,
  right: Right,
  values: Values,
  storeNames: {
    left: StoreNamesAndConfigs,
    right: _flipStoreNames(StoreNamesAndConfigs)
  }
});
;// CONCATENATED MODULE: ./src/sdk/storage/types.ts
var _Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;

/*:: export type Error = {
  name: string;
  message: string;
}*/
var KeyRangeCondition;
(function (KeyRangeCondition) {
  KeyRangeCondition["LowerBound"] = "lowerBound";
  KeyRangeCondition["UpperBound"] = "upperBound";
})(KeyRangeCondition || (KeyRangeCondition = {}));
/*:: export type StoredValue = string | number*/
/*:: export type StoredRecordId = StoredValue | Array<StoredValue>*/
/*:: export type StoredRecord = Record<string, StoredValue | Record<string, StoredValue>>*/
/*:: export interface IStorage {
  getAll: (storeName: string, firstOnly?: boolean) => Promise<Array<StoredRecord>>;
  getFirst: (storeName: string) => Promise<Maybe<StoredRecord>>;
  getItem: (storeName: string, id: StoredRecordId) => Promise<StoredRecord>;
  filterBy: (storeName: string, by: StoredValue) => Promise<Array<StoredRecord>>;
  addItem: (storeName: string, target: StoredRecord) => Promise<StoredRecordId>;
  addBulk: (storeName: string, records: Array<StoredRecord>, overwrite: boolean) => Promise<Array<StoredRecordId>>;
  updateItem: (storeName: string, target: StoredRecord) => Promise<StoredRecordId>;
  deleteItem: (storeName: string, id: StoredRecordId) => Promise<StoredRecordId>;
  deleteBulk: (storeName: string, value: StoredValue, condition?: KeyRangeCondition) => Promise<Array<StoredRecordId>>;
  trimItems: (storeName: string, length: number) => Promise<Array<StoredRecordId>>;
  count: (storeName: string) => Promise<number>;
  clear: (storeName: string) => Promise<void>;
  destroy: () => void;
}*/
function valueIsRecord(value /*: StoredValue | Record<string, unknown>*/) /*: value is Record<string, unknown>*/{
  return isObject(value);
}
;// CONCATENATED MODULE: ./src/sdk/storage/converter.ts







var Direction;
(function (Direction) {
  Direction["right"] = "right";
  Direction["left"] = "left";
})(Direction || (Direction = {}));
/**
 * Get value from the map if available
 */
function _getValue(map /*: Nullable<Record<string, StoredValue>>*/, value /*: StoredValue*/) /*: StoredValue*/{
  return map ? map[value] !== undefined ? map[value] : value : value;
}

/**
 * Convert key and value by defined scheme
 */
function _convert(storeName /*: StoreNameType*/, dir /*: Direction*/, key /*: string*/, value /*: StoredValue | StoredRecord*/, scheme /*: StoreFieldScheme*/) /*: [string, unknown]*/{
  if (!scheme) {
    return [key, value];
  }
  var encodedKey = isComplexStoreField(scheme) ? scheme.key : scheme;
  if (valueIsRecord(value)) {
    var keys = isNestingStoreField(scheme) ? scheme.keys : null;
    return [encodedKey, convertRecord(storeName, dir, value, keys)];
  }
  var valuesMap = isPredefinedValuesField(scheme) ? scheme.values : null;
  return [encodedKey, _getValue(valuesMap, value)];
}

/**
 * Convert record by defined direction and scheme
 */

/**
 * Convert record by defined direction and scheme
 * Note: the function signature is duplicated because TS hides function implementation
 */
function convertRecord(storeName /*: StoreNameType*/, dir /*: Direction*/, record /*: Maybe<StoredRecord>*/, scheme /*: StoreFields*/) /*: Maybe<StoredRecord>*/{
  if (!record) {
    return undefined;
  }
  var _scheme /*: StoreFields*/ = scheme || scheme_map[dir][convertStoreName(storeName, Direction.right)].fields;
  return entries(record).map(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 2),
      key = _ref2[0],
      value = _ref2[1];
    return _convert(storeName, dir, key, value, _scheme[key]);
  }).reduce(function (acc, _ref3) {
    var _ref4 = _slicedToArray(_ref3, 2),
      key = _ref4[0],
      value = _ref4[1];
    return _objectSpread2(_objectSpread2({}, acc), {}, _defineProperty({}, key, value));
  }, {});
}

/**
 * Convert records by defined direction
 */
function convertRecords(storeName /*: StoreNameType*/, dir /*: Direction*/) /*: Array<StoredRecord>*/{
  var records /*: Array<StoredRecord>*/ = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : [];
  return records.map(function (record) {
    return convertRecord(storeName, dir, record);
  });
}

/**
 * Convert values by defined direction
 */
function convertValues(storeName /*: StoreNameType*/, dir /*: Direction*/, target /*: StoredRecordId*/) /*: StoredValue | Array<StoredValue>*/{
  var scheme /*: StoreOptions*/ = scheme_map[dir][convertStoreName(storeName, Direction.right)];
  var keyPathScheme = scheme.fields[scheme.keyPath];
  var values = target instanceof Array ? target.slice() : [target];
  var keys = isCompositeKeyStoreField(keyPathScheme) ? keyPathScheme.composite : [scheme.keyPath];
  var converted = keys.map(function (key /*: string*/, index /*: number*/) {
    var field = scheme.fields[key];
    var predefinedValuesMap = isPredefinedValuesField(field) ? field.values : null;
    return _getValue(predefinedValuesMap, values[index]);
  });
  return converted.length === 1 ? converted[0] : converted;
}

/**
 * Encode value by defined scheme
 */
function encodeValue(target /*: StoredValue*/) /*: StoredValue*/{
  return scheme_map.values[target] || target;
}

/**
 * Convert store name by defined direction
 */
function convertStoreName(storeName /*: StoreNameType*/, dir /*: Direction*/) /*: StoreNameType*/{
  return (scheme_map.storeNames[dir][storeName] || {}).name || storeName;
}

/**
 * Decode error message by replacing short store name with long readable one
 */
function decodeErrorMessage(storeName /*: ShortStoreNames*/, error /*: Error*/) /*: Error*/{
  return {
    name: error.name,
    message: error.message.replace("\"".concat(storeName, "\""), convertStoreName(storeName, Direction.right))
  };
}

;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/classCallCheck.js
function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/createClass.js
function _defineProperties(target, props) {
  for (var i = 0; i < props.length; i++) {
    var descriptor = props[i];
    descriptor.enumerable = descriptor.enumerable || false;
    descriptor.configurable = true;
    if ("value" in descriptor) descriptor.writable = true;
    Object.defineProperty(target, descriptor.key, descriptor);
  }
}
function _createClass(Constructor, protoProps, staticProps) {
  if (protoProps) _defineProperties(Constructor.prototype, protoProps);
  if (staticProps) _defineProperties(Constructor, staticProps);
  Object.defineProperty(Constructor, "prototype", {
    writable: false
  });
  return Constructor;
}
;// CONCATENATED MODULE: ./src/sdk/time.js

/**
 * Prepend zero to be used in certain format
 *
 * @param {number} value
 * @param {number} power
 * @returns {string}
 * @private
 */
function _prependZero(value /*: number*/) /*: string*/{
  var power /*: number*/ = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 1;
  var formatted = value + '';
  for (var i = 1; i <= power; i += 1) {
    if (value < Math.pow(10, i)) {
      formatted = "0".concat(formatted);
    }
  }
  return formatted;
}

/**
 * Get formatted date (YYYY-MM-DD)
 *
 * @param date
 * @returns {string}
 * @private
 */
function _getDate(date /*: Date*/) /*: string*/{
  var day = _prependZero(date.getDate());
  var month = _prependZero(date.getMonth() + 1);
  var year = date.getFullYear();
  return [year, month, day].join('-');
}

/**
 * Get formatted hours, minutes, seconds and milliseconds (HH:mm:ss.SSS)
 *
 * @param {Date} date
 * @returns {string}
 * @private
 */
function _getTime(date /*: Date*/) /*: string*/{
  var hours = _prependZero(date.getHours(), 1);
  var minutes = _prependZero(date.getMinutes());
  var seconds = _prependZero(date.getSeconds());
  var milliseconds = _prependZero(date.getMilliseconds(), 2);
  return [hours, minutes, seconds].join(':') + '.' + milliseconds;
}

/**
 * Get formatted timezone (ZZ)
 *
 * @param {Date} date
 * @returns {string}
 * @private
 */
function _getTimezone(date /*: Date*/) /*: string*/{
  var offsetInMinutes = date.getTimezoneOffset();
  var hoursOffset = _prependZero(Math.floor(Math.abs(offsetInMinutes) / 60));
  var minutesOffset = _prependZero(Math.abs(offsetInMinutes) % 60);
  var sign = offsetInMinutes > 0 ? '-' : '+';
  return sign + hoursOffset + minutesOffset;
}

/**
 * Get the timestamp in the backend format
 *
 * @param {number=} timestamp
 * @returns {string}
 */
function getTimestamp(timestamp /*: number*/) /*: string*/{
  var d = timestamp ? new Date(timestamp) : new Date();
  var date = _getDate(d);
  var time = _getTime(d);
  var timezone = _getTimezone(d);
  return "".concat(date, "T").concat(time, "Z").concat(timezone);
}

/**
 * Calculate time passed between two dates in milliseconds
 *
 * @param {number} d1
 * @param {number} d2
 * @returns {number}
 */
function timePassed(d1 /*: number*/, d2 /*: number*/) /*: number*/{
  if (isNaN(d1) || isNaN(d2)) {
    return 0;
  }
  return Math.abs(d2 - d1);
}

;// CONCATENATED MODULE: ./src/sdk/activity-state.js

/*:: // 
import { type UrlT, type ActivityStateMapT, type AttributionMapT, type CommonRequestParams } from './types';*/






/**
 * Reference to the activity state
 *
 * @type {Object}
 * @private
 */
var _activityState /*: ActivityStateMapT*/ = {};

/**
 * Started flag, if activity state has been initiated
 *
 * @type {boolean}
 * @private
 */
var _started /*: boolean*/ = false;

/**
 * Active flag, if in foreground
 *
 * @type {boolean}
 * @private
 */
var _active /*: boolean*/ = false;

/**
 * Opened flag, if site has been opened
 * 
 * @type {boolean}
 * @private 
 */
var _newlyOpened /*: Boolean*/ = false;

/**
 * Refresh Web Site flag, if site has been refresh
 * If set to true, it indicates that the website has been refreshed, otherwise, it's false.
 * @type {boolean}
 * @private 
 */
var _refreshWebSite /*: Boolean*/ = false;

/**
 * Get current activity state
 *
 * @returns {Object}
 */
function currentGetter() /*: ActivityStateMapT*/{
  return _started ? _objectSpread2({}, _activityState) : {};
}

/**
 * Set current activity state
 *
 * @param {Object} params
 */
function currentSetter() {
  var params /*: ActivityStateMapT*/ = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
  _activityState = _started ? _objectSpread2({}, params) : {};
}

/**
 * Initiate in-memory activity state
 *
 * @param {Object} params
 */
function init(params /*: ActivityStateMapT*/) {
  _newlyOpened = true;
  _started = true;
  currentSetter(params);
  checkRefreshWebSite();
}
function checkRefreshWebSite() /*: Boolean*/{
  // You can also check if it's the first time the page was opened in the session
  if (sessionStorage.getItem('pageLoaded') === null) {
    _refreshWebSite = false;
    sessionStorage.setItem('pageLoaded', 'true');
  } else {
    _refreshWebSite = true;
  }
}
/**
 * Check if activity state is started
 *
 * @returns {boolean}
 */
function isStarted() {
  return _started;
}

/**
 * Check if site newly opened
 * 
 * @returns {boolean}
 */
function isNewlyOpened() {
  return _newlyOpened;
}

/**
 * Check if site refresh
 * 
 * @returns {boolean}
 */
function isRefreshWebSite() {
  return _refreshWebSite;
}

/**
 * Update last active point
 *
 * @private
 */
function updateLastActive() /*: void*/{
  if (!_started) {
    return;
  }
  _activityState.lastInterval = _getLastInterval();
  _activityState.lastActive = Date.now();
}

/**
 * Update activity state with new params
 *
 * @param {Object} params
 * @private
 */
function _update(params /*: ActivityStateMapT*/) /*: void*/{
  _activityState = _objectSpread2(_objectSpread2({}, _activityState), params);
}

/**
 * Set active flag to true when going foreground
 */
function toForeground() /*: void*/{
  _active = true;
}

/**
 * Set active flag to false when going background
 */
function toBackground() /*: void*/{
  _newlyOpened = false;
  _active = false;
}

/**
 * Get time offset from the last active point
 *
 * @returns {number}
 * @private
 */
function _getOffset() /*: number*/{
  var lastActive = _activityState.lastActive;
  return Math.round(timePassed(lastActive, Date.now()) / SECOND);
}

/**
 * Get time spent with optional offset from last point
 *
 * @returns {number}
 * @private
 */
function _getTimeSpent() /*: number*/{
  return (_activityState.timeSpent || 0) + (_active ? _getOffset() : 0);
}

/**
 * Get session length with optional offset from last point
 *
 * @returns {number}
 * @private
 */
function _getSessionLength() /*: number*/{
  var lastActive = _activityState.lastActive;
  var withinWindow = timePassed(lastActive, Date.now()) < config.sessionWindow;
  var withOffset = _active || !_active && withinWindow;
  return (_activityState.sessionLength || 0) + (withOffset ? _getOffset() : 0);
}

/**
 * Get total number of sessions so far
 *
 * @returns {number}
 * @private
 */
function _getSessionCount() /*: number*/{
  return _activityState.sessionCount || 0;
}

/**
 * Get total number of events so far
 *
 * @returns {number}
 * @private
 */
function _getEventCount() /*: number*/{
  return _activityState.eventCount || 0;
}

/**
 * Get time passed since last activity was recorded
 *
 * @returns {number}
 * @private
 */
function _getLastInterval() /*: number*/{
  var lastActive = _activityState.lastActive;
  if (lastActive) {
    return Math.round(timePassed(lastActive, Date.now()) / SECOND);
  }
  return -1;
}

/**
 * Initiate session params and go to foreground
 */
function initParams() /*: void*/{
  updateSessionOffset();
  toForeground();
}

/**
 * Get activity state params that are sent with each request
 *
 * @returns {Object}
 */
function getParams(url /*: UrlT*/) /*: ?CommonRequestParams*/{
  if (!_started) {
    return null;
  }
  var lastInterval = _activityState.lastInterval >= 0 ? _activityState.lastInterval : 0;
  var baseParams /*: CommonRequestParams*/ = {
    timeSpent: _activityState.timeSpent || 0,
    sessionLength: _activityState.sessionLength || 0,
    sessionCount: _activityState.sessionCount || 1,
    lastInterval: lastInterval || 0
  };
  if (url && isRequestEvent(url, 'event')) {
    baseParams.eventCount = _activityState.eventCount;
  }
  return baseParams;
}

/**
 * Update activity state parameters depending on the endpoint which has been run
 *
 * @param {string} url
 * @param {boolean=false} auto
 */
function updateParams(url /*: string*/, auto /*: boolean*/) /*: void*/{
  if (!_started) {
    return;
  }
  var params = {};
  params.timeSpent = _getTimeSpent();
  params.sessionLength = _getSessionLength();
  if (isRequestSession(url, 'session')) {
    params.sessionCount = _getSessionCount() + 1;
  }
  if (isRequestEvent(url, 'event')) {
    params.eventCount = _getEventCount() + 1;
  }
  _update(params);
  if (!auto) {
    updateLastActive();
  }
}

/**
 * Update installed flag - first session has been finished
 */
function updateInstalled() /*: void*/{
  if (!_started) {
    return;
  }
  if (_activityState.installed) {
    return;
  }
  _update({
    installed: true
  });
}

/**
 * Update session params which depend on the time offset since last measure point
 */
function updateSessionOffset() /*: void*/{
  if (!_started) {
    return;
  }
  var timeSpent = _getTimeSpent();
  var sessionLength = _getSessionLength();
  _update({
    timeSpent: timeSpent,
    sessionLength: sessionLength
  });
  updateLastActive();
}

/**
 * Update session length
 */
function updateSessionLength() /*: void*/{
  if (!_started) {
    return;
  }
  var sessionLength = _getSessionLength();
  _update({
    sessionLength: sessionLength
  });
  updateLastActive();
}

/**
 * Reset time spent and session length to zero
 */
function resetSessionOffset() /*: void*/{
  if (!_started) {
    return;
  }
  _update({
    timeSpent: 0,
    sessionLength: 0
  });
}

/**
 * Destroy current activity state
 */
function activity_state_destroy() /*: void*/{
  _activityState = {};
  _started = false;
  _active = false;
}
function getAttribution() /*: AttributionMapT | null*/{
  if (!_started) {
    return null;
  }
  if (!_activityState.attribution) {
    sdk_logger.log('No attribution data yet');
    return null;
  }
  return _activityState.attribution;
}
function getWebUUID() /*: string*/{
  if (!_started) {
    return null;
  }
  return _activityState.uuid;
}
var ActivityState = {
  get current() {
    return currentGetter();
  },
  set current(value) {
    currentSetter(value);
  },
  init: init,
  isStarted: isStarted,
  isNewlyOpened: isNewlyOpened,
  isRefreshWebSite: isRefreshWebSite,
  toForeground: toForeground,
  toBackground: toBackground,
  initParams: initParams,
  getParams: getParams,
  updateParams: updateParams,
  updateInstalled: updateInstalled,
  updateSessionOffset: updateSessionOffset,
  updateSessionLength: updateSessionLength,
  resetSessionOffset: resetSessionOffset,
  updateLastActive: updateLastActive,
  destroy: activity_state_destroy,
  getAttribution: getAttribution,
  getWebUUID: getWebUUID
};
/* harmony default export */ const activity_state = (ActivityState);
;// CONCATENATED MODULE: ./src/sdk/pub-sub.js


/*:: type CallbackT<T> = {|
  id: string,
  cb: (string, T) => mixed
|}*/
/**
 * List of events with subscribed callbacks
 *
 * @type {Object}
 * @private
 */
var _list = {};

/**
 * Reference to timeout ids so they can be cleared on destroy
 *
 * @type {Array}
 * @private
 */
var _timeoutIds = [];

/**
 * Get unique id for the callback to use for unsubscribe
 *
 * @returns {string}
 * @private
 */
function _getId() /*: string*/{
  return 'id' + Math.random().toString(36).substr(2, 16);
}

/**
 * Subscribe to a certain event
 *
 * @param {string} name
 * @param {Function} cb
 * @returns {string}
 */
function subscribe /*:: <T>*/(name /*: string*/, cb /*: $PropertyType<CallbackT<T>, 'cb'>*/) /*: string*/{
  var id = _getId();
  var callback /*: CallbackT<T>*/ = {
    id: id,
    cb: cb
  };
  if (!_list[name]) {
    _list[name] = [];
  }
  _list[name].push(callback);
  return id;
}

/**
 * Unsubscribe particular callback from an event
 *
 * @param {string} id
 */
function unsubscribe(id /*: string*/) /*: void*/{
  if (!id) {
    return;
  }
  entries(_list).some(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 2),
      callbacks = _ref2[1];
    return callbacks.some(function
      /*:: <T>*/
    (callback /*: CallbackT<T>*/, i /*: number*/) {
      if (callback.id === id) {
        callbacks.splice(i, 1);
        return true;
      }
    });
  });
}

/**
 * Publish certain event with optional arguments
 *
 * @param {string} name
 * @param {*} args
 * @returns {Array}
 */
function publish /*:: <T>*/(name /*: string*/, args /*: T*/) /*: void*/{
  if (!_list[name]) {
    return;
  }
  _list[name].forEach(function (item /*: CallbackT<T>*/) {
    if (typeof item.cb === 'function') {
      _timeoutIds.push(setTimeout(function () {
        return item.cb(name, args);
      }));
    }
  });
}

/**
 * Destroy all registered events with their callbacks
 */
function pub_sub_destroy() /*: void*/{
  _timeoutIds.forEach(clearTimeout);
  _timeoutIds = [];
  _list = {};
}

;// CONCATENATED MODULE: ./src/sdk/storage/quick-storage.ts









var InMemoryStorage = /*#__PURE__*/function () {
  function InMemoryStorage() {
    _classCallCheck(this, InMemoryStorage);
    _defineProperty(this, "items", {});
  }
  _createClass(InMemoryStorage, [{
    key: "getItem",
    value: function getItem(key /*: string*/) /*: string | null*/{
      return Object.prototype.hasOwnProperty.call(this.items, key) ? this.items[key] : null;
    }
  }, {
    key: "removeItem",
    value: function removeItem(key /*: string*/) /*: void*/{
      delete this.items[key];
    }
  }, {
    key: "setItem",
    value: function setItem(key /*: string*/, value /*: string*/) /*: void*/{
      this.items[key] = value;
    }
  }]);
  return InMemoryStorage;
}();
var QuickStorage = /*#__PURE__*/function () {
  function QuickStorage() {
    var _this = this;
    _classCallCheck(this, QuickStorage);
    _defineProperty(this, "defaultName", globals.namespace);
    _defineProperty(this, "storageName", this.defaultName);
    _defineProperty(this, "storeNames", scheme_map.storeNames.left);
    _defineProperty(this, "storesMap", void 0);
    _defineProperty(this, "storage", void 0);
    this.storesMap = {};
    if (isLocalStorageSupported()) {
      this.storage = window.localStorage;
    } else {
      this.storage = new InMemoryStorage();
    }
    var read = this.read.bind(this);
    var write = this.write.bind(this);
    values(this.storeNames).forEach(function (store) {
      var shortStoreName = store.name;
      Object.defineProperty(_this.storesMap, shortStoreName, {
        get: function get() {
          return read(shortStoreName);
        },
        set: function set(value) {
          write(shortStoreName, value);
        }
      });
    });
    Object.freeze(this.storesMap);
  }

  /**
   * Sets custom name to use in data keys and updates existing keys in localStorage
   */
  _createClass(QuickStorage, [{
    key: "read",
    value:
    /**
     * Get the value for specified key
     */
    function read(key /*: ShortStoreName | ShortPreferencesStoreName*/) /*: Nullable<StoreContent>*/{
      var valueToParse = this.storage.getItem("".concat(this.storageName, ".").concat(key));
      var value = valueToParse ? JSON.parse(valueToParse) : null;
      if (key === ShortPreferencesStoreName.Preferences && value) {
        return convertRecord(ShortPreferencesStoreName.Preferences, Direction.right, value);
      }
      return value;
    }

    /**
     * Set the value for specified key
     */
  }, {
    key: "write",
    value: function write(key /*: ShortStoreName | ShortPreferencesStoreName*/, value /*: StoreContent*/) {
      if (!value) {
        this.storage.removeItem("".concat(this.storageName, ".").concat(key));
      } else {
        this.storage.setItem("".concat(this.storageName, ".").concat(key), JSON.stringify(value instanceof Array ? value : convertRecord(ShortPreferencesStoreName.Preferences, Direction.left, value)));
      }
    }

    /**
     * Clear all data related to the sdk
     */
  }, {
    key: "clear",
    value: function clear() {
      this.deleteData();
    }

    /**
     * Clear all data related to the sdk
     *
     * @param wipe if true then also remove permanent data such as user's preferences
     */
  }, {
    key: "deleteData",
    value: function deleteData() {
      var _this2 = this;
      var wipe = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;
      values(this.storeNames).forEach(function (store) {
        if (wipe || !store.permanent) {
          _this2.storage.removeItem("".concat(_this2.storageName, ".").concat(store.name));
        }
      });
    }
  }, {
    key: "setCustomName",
    value: function setCustomName(customName /*: string*/) {
      var _this3 = this;
      if (!customName || !customName.length) {
        return;
      }
      var newName = "".concat(globals.namespace, "-").concat(customName);

      // Clone data
      values(this.storeNames).forEach(function (store) {
        var key = store.name;
        var rawData = _this3.storage.getItem("".concat(_this3.storageName, ".").concat(key)); // Get data from the store, no need to encode it
        if (rawData) {
          _this3.storage.setItem("".concat(newName, ".").concat(key), rawData); // Put data into a new store
        }
      });

      this.deleteData(true);
      this.storageName = newName;
    }
  }, {
    key: "stores",
    get: function get() {
      return this.storesMap;
    }
  }]);
  return QuickStorage;
}();
/* harmony default export */ const quick_storage = (new QuickStorage());
;// CONCATENATED MODULE: ./src/sdk/preferences.js





/*:: type SdkDisabledT = {|
  reason: REASON_GENERAL | REASON_GDPR,
  pending: boolean
|}*/
/*:: type ThirdPartySharingDisabledT = {|
  reason: REASON_GENERAL,
  pending: boolean
|}*/
/*:: type PreferencesT = {|
  thirdPartySharingDisabled?: ?ThirdPartySharingDisabledT,
  sdkDisabled?: ?SdkDisabledT
|}*/
/**
 * Name of the store used by preferences
 *
 * @type {string}
 * @private
 */
var _storeName /*: string*/ = storage_scheme.preferences.name;

/**
 * Local reference to be used for recovering preserved state
 *
 * @type {Object}
 * @private
 */
var _preferences /*: ?PreferencesT*/ = _getPreferences();

/**
 * Get preferences stored in the localStorage
 *
 * @returns {Object}
 * @private
 */
function _getPreferences() /*: ?PreferencesT*/{
  if (!_preferences) {
    _setPreferences();
  }
  return _preferences ? _objectSpread2({}, _preferences) : null;
}

/**
 * Set local reference of the preserved preferences
 *
 * @private
 */
function _setPreferences() /*: void*/{
  _preferences = quick_storage.stores[_storeName];
}

/**
 * Get current disabled state
 *
 * @returns {Object|null}
 */
function getDisabled() /*: ?SdkDisabledT*/{
  var preferences = _getPreferences();
  return preferences ? preferences.sdkDisabled : null;
}

/**
 * Set current disabled state
 *
 * @param {Object|null} value
 */
function setDisabled(value /*: ?SdkDisabledT*/) /*: void*/{
  var sdkDisabled = value ? _objectSpread2({}, value) : null;
  quick_storage.stores[_storeName] = _objectSpread2(_objectSpread2({}, _getPreferences()), {}, {
    sdkDisabled: sdkDisabled
  });
  _setPreferences();
}

/**
 * Get current third-party-sharing disabled state
 *
 * @returns {Object}
 * @private
 */
function getThirdPartySharing() /*: ?ThirdPartySharingDisabledT*/{
  var preferences = _getPreferences();
  return preferences ? preferences.thirdPartySharingDisabled : null;
}

/**
 * Set current third-party-sharing disabled state
 *
 * @param {Object=} value
 * @private
 */
function setThirdPartySharing(value /*: ?ThirdPartySharingDisabledT*/) /*: void*/{
  var thirdPartySharingDisabled = value ? _objectSpread2({}, value) : null;
  quick_storage.stores[_storeName] = _objectSpread2(_objectSpread2({}, _getPreferences()), {}, {
    thirdPartySharingDisabled: thirdPartySharingDisabled
  });
  _setPreferences();
}

/**
 * Reload current preferences from localStorage if changed outside of current scope (e.g. tab)
 */
function reload() /*: void*/{
  var stored /*: PreferencesT*/ = quick_storage.stores[_storeName] || {};
  var sdkDisabled /*: ?SdkDisabledT*/ = (_preferences || {}).sdkDisabled || null;
  if (stored.sdkDisabled && !sdkDisabled) {
    publish('sdk:shutdown');
  }
  _setPreferences();
}

/**
 * Recover preferences from memory if storage was lost
 */
function recover() /*: void*/{
  var stored /*: ?PreferencesT*/ = quick_storage.stores[_storeName];
  if (!stored) {
    quick_storage.stores[_storeName] = _objectSpread2({}, _preferences);
  }
}

;// CONCATENATED MODULE: ./src/sdk/storage/indexeddb.ts





var indexeddb_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;










var Action;
(function (Action) {
  Action["add"] = "add";
  Action["put"] = "put";
  Action["get"] = "get";
  Action["list"] = "list";
  Action["clear"] = "clear";
  Action["delete"] = "delete";
})(Action || (Action = {}));
var AccessMode;
(function (AccessMode) {
  AccessMode["readonly"] = "readonly";
  AccessMode["readwrite"] = "readwrite";
})(AccessMode || (AccessMode = {}));
var IndexedDBWrapper = /*#__PURE__*/function () {
  function IndexedDBWrapper() {
    _classCallCheck(this, IndexedDBWrapper);
    _defineProperty(this, "dbDefaultName", globals.namespace);
    _defineProperty(this, "dbName", this.dbDefaultName);
    _defineProperty(this, "dbVersion", 1);
    _defineProperty(this, "idbFactory", void 0);
    _defineProperty(this, "indexedDbConnection", null);
    _defineProperty(this, "notSupportedError", {
      name: 'IDBNotSupported',
      message: 'IndexedDB is not supported'
    });
    _defineProperty(this, "databaseOpenError", {
      name: 'CannotOpenDatabaseError',
      message: 'Cannot open a database'
    });
    _defineProperty(this, "noConnectionError", {
      name: 'NoDatabaseConnection',
      message: 'Cannot open a transaction'
    });
    var idb = IndexedDBWrapper.getIndexedDB();
    if (!idb) {
      throw this.notSupportedError;
    }
    this.idbFactory = idb;
  }

  /**
   * Sets custom name if provided and migrates database
   */
  _createClass(IndexedDBWrapper, [{
    key: "setCustomName",
    value: function setCustomName(customName /*: string*/) /*: Promise<void>*/{
      if (customName && customName.length > 0) {
        this.dbName = "".concat(globals.namespace, "-").concat(customName);
        return this.migrateDb(this.dbDefaultName, this.dbName);
      }
      return indexeddb_Promise.resolve();
    }

    /**
     * Opens database with defined name and resolves with database connection if successed
     * @param name name of database to open
     * @param version optional version of database schema
     * @param upgradeCallback optional `IDBOpenRequest.onupgradeneeded` event handler
     */
  }, {
    key: "openDatabase",
    value: function openDatabase(name /*: string*/, upgradeCallback /*: (event: IDBVersionChangeEvent, reject: () => void) => void*/, version /*: number*/) /*: Promise<IDBDatabase>*/{
      var _this = this;
      return IndexedDBWrapper.isSupported().then(function (supported) {
        if (!supported) {
          return indexeddb_Promise.reject(_this.notSupportedError);
        } else {
          return new indexeddb_Promise(function (resolve, reject) {
            var request = _this.idbFactory.open(name, version);
            if (upgradeCallback) {
              request.onupgradeneeded = function (event) {
                return upgradeCallback(event, reject);
              };
            }
            request.onsuccess = function (event /*: IDBOpenDBEvent*/) {
              var connection = event.target.result;
              if (connection) {
                resolve(connection);
              } else {
                reject(_this.databaseOpenError);
              }
            };
            request.onerror = reject;
          });
        }
      });
    }

    /**
     * Checks if database with passed name exists
     */
  }, {
    key: "databaseExists",
    value: function databaseExists(name /*: string*/) /*: Promise<boolean>*/{
      var _this2 = this;
      return new indexeddb_Promise(function (resolve /*: (result: boolean) => void*/) {
        var existed = true;
        _this2.openDatabase(name, function () {
          existed = false;
        }).then(function (connection) {
          connection.close();
          if (existed) {
            return;
          }

          // We didn't have this database before the check, so remove it
          return _this2.deleteDatabaseByName(name);
        }).then(function () {
          return resolve(existed);
        });
      });
    }
  }, {
    key: "cloneData",
    value: function cloneData(defaultDbConnection /*: IDBDatabase*/, customDbConnection /*: IDBDatabase*/) /*: Promise<void>*/{
      var _this3 = this;
      // Function to clone a single store
      var cloneStore = function cloneStore(storeName /*: ShortStoreName*/) {
        var connection = _this3.indexedDbConnection;
        _this3.indexedDbConnection = defaultDbConnection;
        return _this3.getAll(storeName) // Get all records from default-named database
        .then(function (records) {
          _this3.indexedDbConnection = customDbConnection;
          if (records.length < 1) {
            // There is no records in the store
            return;
          }
          return _this3.addBulk(storeName, records, true); // Put all records into custom-named database
        }).then(function () {
          _this3.indexedDbConnection = connection; // Restore initial state
        });
      };

      // Type guard to filter stores
      function isStoreName(key /*: ShortStoreNames*/) /*: key is ShortStoreName*/{
        return key !== 'p';
      }

      // Get names of stores
      var storeNames /*: ShortStoreName[]*/ = values(scheme_map.storeNames.left).map(function (store) {
        return store.name;
      }).filter(isStoreName);
      var cloneStorePromises = storeNames.map(function (name) {
        return function () {
          return cloneStore(name);
        };
      });

      // Run clone operations one by one
      return cloneStorePromises.reduce(function (previousTask, currentTask) {
        return previousTask.then(currentTask);
      }, indexeddb_Promise.resolve());
    }

    /**
     * Migrates created database with default name to custom
     * The IndexedDb API doesn't provide method to rename existing database so we have to create a new database, clone
     * data and remove the old one.
     */
  }, {
    key: "migrateDb",
    value: function migrateDb(defaultName /*: string*/, customName /*: string*/) /*: Promise<void>*/{
      var _this4 = this;
      return this.databaseExists(defaultName).then(function (defaultExists) {
        if (defaultExists) {
          // Migration hadn't finished yet
          return indexeddb_Promise.all([_this4.openDatabase(defaultName, _this4.handleUpgradeNeeded, _this4.dbVersion),
          // Open the default database, migrate version if needed
          _this4.openDatabase(customName, _this4.handleUpgradeNeeded, _this4.dbVersion) // Open or create a new database, migrate version if needed
          ]).then(function (_ref) {
            var _ref2 = _slicedToArray(_ref, 2),
              defaultDbConnection = _ref2[0],
              customDbConnection = _ref2[1];
            return _this4.cloneData(defaultDbConnection, customDbConnection).then(function () {
              _this4.indexedDbConnection = customDbConnection;
              defaultDbConnection.close();
              return _this4.deleteDatabaseByName(defaultName);
            });
          }).then(function () {
            return sdk_logger.info('Database migration finished');
          });
        } else {
          // There is no default-named database, let's just create or open a custom-named one
          return _this4.openDatabase(customName, _this4.handleUpgradeNeeded, _this4.dbVersion).then(function (customDbConnection) {
            _this4.indexedDbConnection = customDbConnection;
          });
        }
      });
    }

    /**
     * Handle database upgrade/initialization
     * - store activity state from memory if database unexpectedly got lost in the middle of the window session
     * - migrate data from localStorage if available on browser upgrade
     */
  }, {
    key: "handleUpgradeNeeded",
    value: function handleUpgradeNeeded(e /*: IDBVersionChangeEvent*/, reject /*: (reason: Event) => void*/) {
      var db = e.target.result;
      e.target.transaction.onerror = reject;
      e.target.transaction.onabort = reject;
      var storeNames = scheme_map.storeNames.left;
      var activityState = activity_state.current || {};
      var inMemoryAvailable = activityState && !isEmpty(activityState);
      entries(storeNames).filter(function (_ref3) {
        var _ref4 = _slicedToArray(_ref3, 2),
          store = _ref4[1];
        return !store.permanent;
      }).forEach(function (_ref5) {
        var _ref6 = _slicedToArray(_ref5, 2),
          longStoreName = _ref6[0],
          store = _ref6[1];
        var shortStoreName = store.name;
        var options = scheme_map.right[longStoreName];
        var objectStore = db.createObjectStore(shortStoreName, {
          keyPath: options.keyPath,
          autoIncrement: options.autoIncrement || false
        });
        if (options.index) {
          objectStore.createIndex("".concat(options.index, "Index"), options.index);
        }
        if (shortStoreName === ShortStoreName.ActivityState && inMemoryAvailable) {
          objectStore.add(convertRecord(longStoreName, Direction.left, activityState));
          sdk_logger.info('Activity state has been recovered');
          return;
        }
        var localStorageRecord /*: Nullable<Array<StoredRecord>>*/ = quick_storage.stores[shortStoreName];
        if (localStorageRecord) {
          localStorageRecord.forEach(function (record) {
            return objectStore.add(record);
          });
          sdk_logger.info("Migration from localStorage done for ".concat(longStoreName, " store"));
        }
      });
      recover();
      quick_storage.clear();
    }

    /**
     * Open the database connection and create store if not existent
     */
  }, {
    key: "open",
    value: function open() /*: Promise<{ success: boolean }>*/{
      var _this5 = this;
      if (this.indexedDbConnection) {
        return indexeddb_Promise.resolve({
          success: true
        });
      }
      return this.openDatabase(this.dbName, this.handleUpgradeNeeded, this.dbVersion).then(function (connection) {
        _this5.indexedDbConnection = connection;
        _this5.indexedDbConnection.onclose = function () {
          return _this5.destroy;
        };
        return {
          success: true
        };
      });
    }

    /**
     * Get transaction and the store
     */
  }, {
    key: "getTransactionStore",
    value: function getTransactionStore(_ref7 /*:: */, reject /*: (reason: Event) => void*/, db /*: IDBDatabase*/) /*: Transaction*/{
      var storeName = _ref7 /*:: */.storeName,
        mode = _ref7 /*:: */.mode;
      var transaction /*: IDBTransaction*/ = db.transaction([storeName], mode);
      var store = transaction.objectStore(storeName);
      var options = scheme_map.right[convertStoreName(storeName, Direction.right)];
      var index;
      if (options.index) {
        index = store.index("".concat(options.index, "Index"));
      }
      transaction.onerror = reject;
      transaction.onabort = reject;
      return {
        transaction: transaction,
        store: store,
        index: index,
        options: options
      };
    }

    /**
     * Override the error by extracting only name and message of the error
     */
  }, {
    key: "overrideError",
    value: function overrideError(reject /*: (reason: Error) => void*/, error /*: IDBError*/) {
      var _error$target$error = error.target.error,
        name = _error$target$error.name,
        message = _error$target$error.message;
      return reject({
        name: name,
        message: message
      });
    }

    /**
     * Get list of composite keys if available
     */
  }, {
    key: "getCompositeKeys",
    value: function getCompositeKeys(options /*: StoreOptions*/) /*: Nullable<Array<string>>*/{
      var keyField = options.fields[options.keyPath];
      return isCompositeKeyStoreField(keyField) ? keyField.composite : null;
    }

    /**
     * Check if target is an object
     */
  }, {
    key: "targetIsObject",
    value: function targetIsObject(target /*: Nullable<StoredRecord | StoredRecordId>*/) /*: target is Record<string, StoredValue>*/{
      return isObject(target);
    }

    /**
     * Prepare the target to be queried depending on the composite key if defined
     */
  }, {
    key: "prepareTarget",
    value: function prepareTarget(options /*: StoreOptions*/, target /*: Nullable<StoredRecord | StoredRecordId>*/, action /*: Action*/) /*: Nullable<StoredRecord | StoredRecordId>*/{
      if (action === Action.clear || !target) {
        return null; // No target needed when we clear the whole store
      }

      var composite = this.getCompositeKeys(options);
      var needObjectTarget = [Action.add, Action.put].indexOf(action) !== -1;
      if (needObjectTarget) {
        if (this.targetIsObject(target)) {
          // target is a StoredRecord
          // extend target with composite path if needed and return it
          return composite ? _objectSpread2(_defineProperty({}, options.keyPath, composite.map(function (key) {
            return target[key];
          }).join('')), target) : target;
        }
        return null;
      }

      // target is StoredRecordId (plain or composite)
      return target instanceof Array ? target.join('') : target;
    }

    /**
     * Prepare the result to be return depending on the composite key definition
     */
  }, {
    key: "prepareResult",
    value: function prepareResult(options /*: StoreOptions*/, target /*: Nullable<StoredRecord | StoredRecordId>*/) /*: Nullable<Array<StoredValue>>*/{
      var composite = this.getCompositeKeys(options);
      if (composite && this.targetIsObject(target)) {
        return composite.map(function (key) {
          return target[key];
        });
      }
      return null;
    }

    /**
     * Initiate the database request
     */
  }, {
    key: "initRequest",
    value: function initRequest(_ref8 /*:: */) /*: Promise<Maybe<StoredRecord | StoredRecordId>>*/{
      var _this6 = this;
      var storeName = _ref8 /*:: */.storeName,
        _ref8$target = _ref8 /*:: */.target,
        target = _ref8$target === void 0 ? null : _ref8$target,
        action = _ref8 /*:: */.action,
        _ref8$mode = _ref8 /*:: */.mode,
        mode = _ref8$mode === void 0 ? AccessMode.readonly : _ref8$mode;
      return this.open().then(function () {
        return new indexeddb_Promise(function (resolve, reject) {
          if (!_this6.indexedDbConnection) {
            reject(_this6.noConnectionError);
          } else {
            var _this6$getTransaction = _this6.getTransactionStore({
                storeName: storeName,
                mode: mode
              }, reject, _this6.indexedDbConnection),
              store = _this6$getTransaction.store,
              options = _this6$getTransaction.options;
            var request = store[action](_this6.prepareTarget(options, target, action));
            var _result = _this6.prepareResult(options, target);
            request.onsuccess = function () {
              if (action === Action.get && !request.result) {
                reject({
                  name: 'NotRecordFoundError',
                  message: "Requested record not found in \"".concat(storeName, "\" store")
                });
              } else {
                resolve(_result || request.result || target);
              }
            };
            request.onerror = function (error /*: Event*/) {
              return _this6.overrideError(reject, error);
            };
          }
        });
      });
    }

    /**
     * Initiate bulk database request by reusing the same transaction to perform the operation
     */
  }, {
    key: "initBulkRequest",
    value: function initBulkRequest(_ref9 /*:: */) /*: Promise<Array<StoredRecord | StoredRecordId>>*/{
      var _this7 = this;
      var storeName = _ref9 /*:: */.storeName,
        target = _ref9 /*:: */.target,
        action = _ref9 /*:: */.action,
        _ref9$mode = _ref9 /*:: */.mode,
        mode = _ref9$mode === void 0 ? AccessMode.readwrite : _ref9$mode;
      if (!target || target && !target.length) {
        return indexeddb_Promise.reject({
          name: 'NoTargetDefined',
          message: "No array provided to perform ".concat(action, " bulk operation into \"").concat(storeName, "\" store")
        });
      }
      return this.open().then(function () {
        return new indexeddb_Promise(function (resolve, reject) {
          if (!_this7.indexedDbConnection) {
            reject(_this7.noConnectionError);
          } else {
            var _this7$getTransaction = _this7.getTransactionStore({
                storeName: storeName,
                mode: mode
              }, reject, _this7.indexedDbConnection),
              transaction = _this7$getTransaction.transaction,
              store = _this7$getTransaction.store,
              options = _this7$getTransaction.options;

            // Array contains or StoredRecord either RecordIds, but not both at the same time
            var _result2 = new Array();
            var current = target[0];
            transaction.oncomplete = function () {
              return resolve(_result2);
            };
            var request = function request(req) {
              req.onerror = function (error) {
                return _this7.overrideError(reject, error);
              };
              req.onsuccess = function () {
                _result2.push(_this7.prepareResult(options, current) || req.result);
                current = target[_result2.length];
                if (_result2.length < target.length) {
                  request(store[action](_this7.prepareTarget(options, current, action)));
                }
              };
            };
            request(store[action](_this7.prepareTarget(options, current, action)));
          }
        });
      });
    }

    /**
     * Open cursor for bulk operations or listing
     */
  }, {
    key: "openCursor",
    value: function openCursor(_ref10 /*:: */) /*: Promise<Array<StoredRecord | StoredRecordId>>*/{
      var _this8 = this;
      var storeName = _ref10 /*:: */.storeName,
        action = _ref10 /*:: */.action,
        _ref10$range = _ref10 /*:: */.range,
        range = _ref10$range === void 0 ? null : _ref10$range,
        _ref10$firstOnly = _ref10 /*:: */.firstOnly,
        firstOnly = _ref10$firstOnly === void 0 ? false : _ref10$firstOnly,
        _ref10$mode = _ref10 /*:: */.mode,
        mode = _ref10$mode === void 0 ? AccessMode.readonly : _ref10$mode;
      return this.open().then(function () {
        return new indexeddb_Promise(function (resolve, reject) {
          if (!_this8.indexedDbConnection) {
            reject(_this8.noConnectionError);
          } else {
            var _this8$getTransaction = _this8.getTransactionStore({
                storeName: storeName,
                mode: mode
              }, reject, _this8.indexedDbConnection),
              transaction = _this8$getTransaction.transaction,
              store = _this8$getTransaction.store,
              index = _this8$getTransaction.index,
              options = _this8$getTransaction.options;
            var cursorRequest /*: OpenIDBCursorRequest*/ = (index || store).openCursor(range);
            var items = new Array();
            transaction.oncomplete = function () {
              return resolve(items);
            };
            cursorRequest.onsuccess = function (e) {
              var cursor = e.target.result;
              if (cursor) {
                if (action === Action.delete) {
                  cursor.delete();
                  items.push(_this8.prepareResult(options, cursor.value) || cursor.value[options.keyPath]);
                } else {
                  items.push(cursor.value);
                }
                if (!firstOnly) {
                  cursor.continue();
                }
              }
            };
            cursorRequest.onerror = function (error) {
              return _this8.overrideError(reject, error);
            };
          }
        });
      });
    }
  }, {
    key: "deleteDatabaseByName",
    value: function deleteDatabaseByName(dbName /*: string*/) /*: Promise<void>*/{
      var _this9 = this;
      return new indexeddb_Promise(function (resolve, reject) {
        var request = _this9.idbFactory.deleteDatabase(dbName);
        request.onerror = function (error) {
          return _this9.overrideError(reject, error);
        };
        request.onsuccess = function () {
          return resolve();
        };
        request.onblocked = function (e) {
          return reject(e.target);
        };
      });
    }

    /**
     * Get all records from particular store
     */
  }, {
    key: "getAll",
    value: function getAll(storeName /*: ShortStoreName*/) /*: Promise<Array<StoredRecord>>*/{
      var firstOnly = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      return this.openCursor({
        storeName: storeName,
        action: Action.list,
        firstOnly: firstOnly
      });
    }

    /**
     * Get the first row from the store
     */
  }, {
    key: "getFirst",
    value: function getFirst(storeName /*: ShortStoreName*/) /*: Promise<Maybe<StoredRecord>>*/{
      return this.getAll(storeName, true).then(function (all) {
        return all.length ? all[0] : undefined;
      });
    }

    /**
     * Get item from a particular store
     */
  }, {
    key: "getItem",
    value: function getItem(storeName /*: ShortStoreName*/, target /*: StoredRecordId*/) /*: Promise<StoredRecord>*/{
      return this.initRequest({
        storeName: storeName,
        target: target,
        action: Action.get
      });
    }

    /**
     * Return filtered result by value on available index
     */
  }, {
    key: "filterBy",
    value: function filterBy(storeName /*: ShortStoreName*/, by /*: StoredValue*/) /*: Promise<Array<StoredRecord>>*/{
      var range = IDBKeyRange.only(by);
      return this.openCursor({
        storeName: storeName,
        action: Action.list,
        range: range
      });
    }

    /**
     * Add item to a particular store
     */
  }, {
    key: "addItem",
    value: function addItem(storeName /*: ShortStoreName*/, target /*: StoredRecord*/) /*: Promise<StoredRecordId>*/{
      return this.initRequest({
        storeName: storeName,
        target: target,
        action: Action.add,
        mode: AccessMode.readwrite
      });
    }

    /**
     * Add multiple items into particular store
     */
  }, {
    key: "addBulk",
    value: function addBulk(storeName /*: ShortStoreName*/, target /*: Array<StoredRecord>*/, overwrite /*: boolean*/) /*: Promise<Array<StoredRecordId>>*/{
      return this.initBulkRequest({
        storeName: storeName,
        target: target,
        action: overwrite ? Action.put : Action.add,
        mode: AccessMode.readwrite
      });
    }

    /**
     * Update item in a particular store
     */
  }, {
    key: "updateItem",
    value: function updateItem(storeName /*: ShortStoreName*/, target /*: StoredRecord*/) /*: Promise<StoredRecordId>*/{
      return this.initRequest({
        storeName: storeName,
        target: target,
        action: Action.put,
        mode: AccessMode.readwrite
      });
    }

    /**
     * Delete item from a particular store
     */
  }, {
    key: "deleteItem",
    value: function deleteItem(storeName /*: ShortStoreName*/, target /*: StoredRecordId*/) /*: Promise<StoredRecordId>*/{
      return this.initRequest({
        storeName: storeName,
        target: target,
        action: Action.delete,
        mode: AccessMode.readwrite
      });
    }

    /**
     * Delete items until certain bound (primary key as a bound scope)
     */
  }, {
    key: "deleteBulk",
    value: function deleteBulk(storeName /*: ShortStoreName*/, value /*: StoredValue*/, condition /*: KeyRangeCondition*/) /*: Promise<Array<StoredRecordId>>*/{
      var range = condition ? IDBKeyRange[condition](value) : IDBKeyRange.only(value);
      return this.openCursor({
        storeName: storeName,
        action: Action.delete,
        range: range,
        mode: AccessMode.readwrite
      });
    }

    /**
     * Trim the store from the left by specified length
     */
  }, {
    key: "trimItems",
    value: function trimItems(storeName /*: ShortStoreName*/, length /*: number*/) /*: Promise<Array<StoredRecordId>>*/{
      var _this10 = this;
      var options = scheme_map.right[convertStoreName(storeName, Direction.right)];
      return this.getAll(storeName).then(function (records) {
        return records.length ? records[length - 1] : null;
      }).then(function (record) {
        return record ? _this10.deleteBulk(storeName, record[options.keyPath], KeyRangeCondition.UpperBound) : [];
      });
    }

    /**
     * Count the number of records in the store
     */
  }, {
    key: "count",
    value: function count(storeName /*: ShortStoreName*/) /*: Promise<number>*/{
      var _this11 = this;
      return this.open().then(function () {
        return new indexeddb_Promise(function (resolve, reject) {
          if (!_this11.indexedDbConnection) {
            reject(_this11.noConnectionError);
          } else {
            var _this11$getTransactio = _this11.getTransactionStore({
                storeName: storeName,
                mode: AccessMode.readonly
              }, reject, _this11.indexedDbConnection),
              store = _this11$getTransactio.store;
            var request = store.count();
            request.onsuccess = function () {
              return resolve(request.result);
            };
            request.onerror = function (error) {
              return _this11.overrideError(reject, error);
            };
          }
        });
      });
    }

    /**
     * Clear all records from a particular store
     */
  }, {
    key: "clear",
    value: function clear(storeName /*: ShortStoreName*/) /*: Promise<void>*/{
      return this.initRequest({
        storeName: storeName,
        action: Action.clear,
        mode: AccessMode.readwrite
      });
    }

    /**
     * Close the database and destroy the reference to it
     */
  }, {
    key: "destroy",
    value: function destroy() /*: void*/{
      if (this.indexedDbConnection) {
        this.indexedDbConnection.close();
      }
      this.indexedDbConnection = null;
    }

    /**
     * Close db connection and delete the db
     * WARNING: should be used only by wisetrack's demo app!
     */
  }, {
    key: "deleteDatabase",
    value: function deleteDatabase() /*: Promise<void>*/{
      this.destroy();
      return this.deleteDatabaseByName(this.dbName);
    }
  }], [{
    key: "tryOpen",
    value:
    /**
     * Cached promise of IndexedDB validation
     */

    /**
     * Tries to open a temporary database
     */
    function tryOpen(db /*: IDBFactory*/) /*: Promise<boolean>*/{
      return new indexeddb_Promise(function (resolve) {
        try {
          var request = db.open(IndexedDBWrapper.dbValidationName);
          request.onsuccess = function () {
            request.result.close();
            db.deleteDatabase(IndexedDBWrapper.dbValidationName);
            resolve(true);
          };
          request.onerror = function () {
            return resolve(false);
          };
        } catch (error) {
          resolve(false);
        }
      });
    }

    /**
     * Check if IndexedDB is supported in the current browser (exclude iOS forcefully)
     */
  }, {
    key: "isSupported",
    value: function isSupported() /*: Promise<boolean>*/{
      if (IndexedDBWrapper.isSupportedPromise) {
        return IndexedDBWrapper.isSupportedPromise;
      } else {
        var notSupportedMessage = 'IndexedDB is not supported in this browser';
        IndexedDBWrapper.isSupportedPromise = new indexeddb_Promise(function (resolve) {
          var indexedDB = IndexedDBWrapper.getIndexedDB();
          var iOS = !!navigator.platform && /iPad|iPhone|iPod/.test(navigator.platform);
          if (!indexedDB || iOS) {
            sdk_logger.warn(notSupportedMessage);
            resolve(false);
          } else {
            var dbOpenablePromise = IndexedDBWrapper.tryOpen(indexedDB).then(function (dbOpenable) {
              if (!dbOpenable) {
                sdk_logger.warn(notSupportedMessage);
              }
              return dbOpenable;
            });
            resolve(dbOpenablePromise);
          }
        });
      }
      return IndexedDBWrapper.isSupportedPromise;
    }

    /**
     * Get indexedDB instance
     */
  }, {
    key: "getIndexedDB",
    value: function getIndexedDB() /*: Maybe<IDBFactory>*/{
      return window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
    }
  }]);
  return IndexedDBWrapper;
}();
_defineProperty(IndexedDBWrapper, "dbValidationName", 'validate-db-openable');
_defineProperty(IndexedDBWrapper, "isSupportedPromise", null);

;// CONCATENATED MODULE: ./src/sdk/storage/localstorage.ts






var localstorage_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;









var LocalStorageWrapper = /*#__PURE__*/function () {
  function LocalStorageWrapper() {
    _classCallCheck(this, LocalStorageWrapper);
  }
  _createClass(LocalStorageWrapper, [{
    key: "open",
    value:
    /**
     * Prepare schema details if not existent
     */
    function open() /*: Promise<StorageOpenStatus>*/{
      return LocalStorageWrapper.isSupported().then(function (supported) {
        if (!supported) {
          return {
            status: 'error',
            error: {
              name: 'LSNotSupported',
              message: 'LocalStorage is not supported'
            }
          };
        }
        var storeNames = scheme_map.storeNames.left;
        var activityState = activity_state.current || {};
        var inMemoryAvailable = activityState && !isEmpty(activityState);
        entries(storeNames).filter(function (_ref) {
          var _ref2 = _slicedToArray(_ref, 2),
            store = _ref2[1];
          return !store.permanent;
        }).forEach(function (_ref3) {
          var _ref4 = _slicedToArray(_ref3, 2),
            longStoreName = _ref4[0],
            store = _ref4[1];
          var shortStoreName = store.name;
          if (shortStoreName === ShortStoreName.ActivityState && !quick_storage.stores[shortStoreName]) {
            quick_storage.stores[shortStoreName] = inMemoryAvailable ? [convertRecord(longStoreName, Direction.left, activityState)] : [];
          } else if (!quick_storage.stores[shortStoreName]) {
            quick_storage.stores[shortStoreName] = [];
          }
        });
        recover();
        return {
          status: 'success'
        };
      });
    }

    /**
     * Get list of composite keys if available
     */
  }, {
    key: "getCompositeKeys",
    value: function getCompositeKeys(options /*: StoreOptions*/) /*: Nullable<Array<string>>*/{
      var field = options.fields[options.keyPath];
      return isCompositeKeyStoreField(field) ? field.composite : null;
    }

    /**
     * Get composite keys when defined or fallback to primary key for particular store
     */
  }, {
    key: "getKeys",
    value: function getKeys(storeName /*: ShortStoreName*/) /*: Array<string>*/{
      var name = convertStoreName(storeName, Direction.right);
      var options /*: StoreOptions*/ = scheme_map.right[name];
      return this.getCompositeKeys(options) || [options.keyPath];
    }

    /**
     * Return next index using the current one and undefined if current is undefined
     */
  }, {
    key: "nextIndex",
    value: function nextIndex(current /*: Maybe<number>*/) /*: Maybe<number>*/{
      return typeof current === 'number' ? current + 1 : undefined;
    }

    /**
     * Initiate quasi-database request
     */
  }, {
    key: "initRequest",
    value: function initRequest /*:: <T>*/(_ref5 /*:: */, action /*: Action<T>*/) /*: Promise<T>*/{
      var _this = this;
      var storeName = _ref5 /*:: */.storeName,
        id = _ref5 /*:: */.id,
        item = _ref5 /*:: */.item;
      var options = scheme_map.right[convertStoreName(storeName, Direction.right)];
      return this.open().then(function (open) {
        if (open.status === 'error') {
          return localstorage_Promise.reject(open.error);
        }
        return new localstorage_Promise(function (resolve, reject) {
          var items /*: Array<StoredRecord>*/ = quick_storage.stores[storeName];
          var keys = _this.getKeys(storeName);
          var lastId = (items[items.length - 1] || {})[options.keyPath] || 0;
          var target /*: StoredRecord*/;
          if (!id) {
            target = _objectSpread2({}, item);
          } else {
            var ids = Array.isArray(id) ? id.slice() : [id];
            target = keys.map(function (key, index) {
              return [key, ids[index]];
            }).reduce(reducer, {});
          }
          var index = target ? findIndex(items, keys, target) : 0;
          return action(resolve, reject, {
            keys: keys,
            items: items,
            index: index,
            options: options,
            lastId: lastId
          });
        });
      });
    }

    /**
     * Sort the array by provided key (key can be a composite one)
     * - by default sorts in ascending order by primary keys
     * - force order by provided value
     */
  }, {
    key: "sort",
    value: function sort /*:: <T>*/(items /*: Array<T>*/, keys /*: Array<string>*/, exact /*: Nullable<StoredValue>*/) /*: Array<T>*/{
      var clone = _toConsumableArray(items);
      var reversed = keys.slice().reverse();
      function compare(a /*: T*/, b /*: T*/, key /*: string*/) {
        var expr1 = exact ? exact === a[key] : a[key] < b[key];
        var expr2 = exact ? exact > a[key] : a[key] > b[key];
        return expr1 ? -1 : expr2 ? 1 : 0;
      }
      return clone.sort(function (a, b) {
        return reversed.reduce(function (acc, key) {
          return acc || compare(a, b, key);
        }, 0);
      });
    }

    /**
     * Prepare the target to be queried depending on the composite key if defined
     */
  }, {
    key: "prepareTarget",
    value: function prepareTarget(options /*: StoreOptions*/, target /*: StoredRecord*/, next /*: number*/) /*: StoredRecord*/{
      var composite = this.getCompositeKeys(options);
      return composite ? _objectSpread2(_defineProperty({}, options.keyPath, composite.map(function (key) {
        return target[key];
      }).join('')), target) : options.autoIncrement && next ? _objectSpread2(_defineProperty({}, options.keyPath, next), target) : _objectSpread2({}, target);
    }

    /**
     * Prepare the result to be return depending on the composite key definition
     */
  }, {
    key: "prepareResult",
    value: function prepareResult(options /*: StoreOptions*/, target /*: StoredRecord*/) /*: StoredRecordId*/{
      var composite = this.getCompositeKeys(options);
      if (composite) {
        return composite.map(function (key) {
          return target[key];
        }).filter(function (value) {
          return (/*: value is StoredValue*/!valueIsRecord(value)
          );
        });
      }
      return target[options.keyPath];
    }

    /**
     * Get all records from particular store
     */
  }, {
    key: "getAll",
    value: function getAll(storeName /*: ShortStoreName*/) /*: Promise<Array<StoredRecord>>*/{
      var _this2 = this;
      var firstOnly = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      return this.open().then(function (open) {
        if (open.status === 'error') {
          return localstorage_Promise.reject(open.error);
        }
        return new localstorage_Promise(function (resolve, reject) {
          var value = quick_storage.stores[storeName];
          if (value instanceof Array) {
            resolve(firstOnly ? [value[0]] : _this2.sort(value, _this2.getKeys(storeName)));
          } else {
            reject({
              name: 'NotFoundError',
              message: "No objectStore named ".concat(storeName, " in this database")
            });
          }
        });
      });
    }

    /**
     * Get the first row from the store
     */
  }, {
    key: "getFirst",
    value: function getFirst(storeName /*: ShortStoreName*/) /*: Promise<Maybe<StoredRecord>>*/{
      return this.getAll(storeName, true).then(function (all) {
        return all.length ? all[0] : undefined;
      });
    }

    /**
     * Get item from a particular store
     */
  }, {
    key: "getItem",
    value: function getItem(storeName /*: ShortStoreName*/, id /*: StoredRecordId*/) /*: Promise<StoredRecord>*/{
      var _this3 = this;
      var action /*: Action<StoredRecord>*/ = function action /*: Action<StoredRecord>*/(resolve, reject, _ref6) {
        var items = _ref6.items,
          index = _ref6.index,
          options = _ref6.options;
        if (index === -1) {
          reject({
            name: 'NotRecordFoundError',
            message: "Requested record not found in \"".concat(storeName, "\" store")
          });
        } else {
          resolve(_this3.prepareTarget(options, items[index]));
        }
      };
      return this.initRequest({
        storeName: storeName,
        id: id
      }, action);
    }

    /**
     * Return filtered result by value on available index
     */
  }, {
    key: "filterBy",
    value: function filterBy(storeName /*: ShortStoreName*/, by /*: StoredValue*/) /*: Promise<Array<StoredRecord>>*/{
      return this.getAll(storeName).then(function (result /*: Array<StoredRecord>*/) {
        return result.filter(function (item) {
          var store = scheme_map.right[convertStoreName(storeName, Direction.right)];
          var indexedValue = store.index && item[store.index];
          return indexedValue === by;
        });
      });
    }

    /**
     * Add item to a particular store
     */
  }, {
    key: "addItem",
    value: function addItem(storeName /*: ShortStoreName*/, item /*: StoredRecord*/) /*: Promise<StoredRecordId>*/{
      var _this4 = this;
      return this.initRequest({
        storeName: storeName,
        item: item
      }, function (resolve, reject, _ref7) {
        var items = _ref7.items,
          index = _ref7.index,
          options = _ref7.options,
          lastId = _ref7.lastId;
        if (index !== -1) {
          reject({
            name: 'ConstraintError',
            message: "Constraint was not satisfied, trying to add existing item into \"".concat(storeName, "\" store")
          });
        } else {
          items.push(_this4.prepareTarget(options, item, _this4.nextIndex(lastId)));
          quick_storage.stores[storeName] = items;
          resolve(_this4.prepareResult(options, item));
        }
      });
    }

    /**
     * Add multiple items into particular store
     */
  }, {
    key: "addBulk",
    value: function addBulk(storeName /*: ShortStoreName*/, target /*: Array<StoredRecord>*/, overwrite /*: boolean*/) /*: Promise<Array<StoredRecordId>>*/{
      var _this5 = this;
      return this.initRequest({
        storeName: storeName
      }, function (resolve, reject, _ref8) {
        var keys = _ref8.keys,
          items = _ref8.items,
          options = _ref8.options,
          lastId = _ref8.lastId;
        if (!target || target && !target.length) {
          reject({
            name: 'NoTargetDefined',
            message: "No array provided to perform add bulk operation into \"".concat(storeName, "\" store")
          });
          return;
        }
        var id = lastId;
        var newItems = target.map(function (item) {
          return _this5.prepareTarget(options, item, id = _this5.nextIndex(id));
        });
        var overlapping = newItems.filter(function (item) {
          return findIndex(items, keys, item) !== -1;
        }).map(function (item) {
          return item[options.keyPath];
        });
        var currentItems = overwrite ? items.filter(function (item) {
          return overlapping.indexOf(item[options.keyPath]) === -1;
        }) : _toConsumableArray(items);
        if (overlapping.length && !overwrite) {
          reject({
            name: 'ConstraintError',
            message: "Constraint was not satisfied, trying to add existing items into \"".concat(storeName, "\" store")
          });
        } else {
          quick_storage.stores[storeName] = _this5.sort([].concat(_toConsumableArray(currentItems), _toConsumableArray(newItems)), keys);
          var result = target.map(function (item) {
            return _this5.prepareResult(options, item);
          });
          resolve(result);
        }
      });
    }

    /**
     * Update item in a particular store
     */
  }, {
    key: "updateItem",
    value: function updateItem(storeName /*: ShortStoreName*/, item /*: StoredRecord*/) /*: Promise<StoredRecordId>*/{
      var _this6 = this;
      return this.initRequest({
        storeName: storeName,
        item: item
      }, function (resolve, _, _ref9) {
        var items = _ref9.items,
          index = _ref9.index,
          options = _ref9.options,
          lastId = _ref9.lastId;
        var nextId = index === -1 ? _this6.nextIndex(lastId) : undefined;
        var target = _this6.prepareTarget(options, item, nextId);
        if (index === -1) {
          items.push(target);
        } else {
          items.splice(index, 1, target);
        }
        quick_storage.stores[storeName] = items;
        resolve(_this6.prepareResult(options, item));
      });
    }

    /**
     * Delete item from a particular store
     */
  }, {
    key: "deleteItem",
    value: function deleteItem(storeName /*: ShortStoreName*/, id /*: StoredRecordId*/) /*: Promise<StoredRecordId>*/{
      return this.initRequest({
        storeName: storeName,
        id: id
      }, function (resolve, _, _ref10) {
        var items = _ref10.items,
          index = _ref10.index;
        if (index !== -1) {
          items.splice(index, 1);
          quick_storage.stores[storeName] = items;
        }
        resolve(id);
      });
    }

    /**
     * Find index of the item with the closest value to the bound
     */
  }, {
    key: "findMax",
    value: function findMax(array /*: Array<StoredRecord>*/, key /*: string*/, value /*: StoredValue*/) /*: number*/{
      if (!array.length) {
        return -1;
      }
      var max = {
        index: -1,
        value: typeof value === 'string' ? '' : 0
      };
      for (var i = 0; i < array.length; i += 1) {
        if (array[i][key] <= value) {
          if (array[i][key] >= max.value) {
            max = {
              value: array[i][key],
              index: i
            };
          }
        } else {
          return max.index;
        }
      }
      return max.index;
    }

    /**
     * Delete items until certain bound (primary key as a bound scope)
     * Returns array of deleted elements
     */
  }, {
    key: "deleteBulk",
    value: function deleteBulk(storeName /*: ShortStoreName*/, value /*: StoredValue*/, condition /*: KeyRangeCondition*/) /*: Promise<Array<StoredRecordId>>*/{
      var _this7 = this;
      return this.getAll(storeName).then(function (items /*: Array<StoredRecord>*/) {
        var keys = _this7.getKeys(storeName);
        var key = scheme_map.right[convertStoreName(storeName, Direction.right)].index || keys[0];
        var exact = condition ? null : value;
        var sorted /*: Array<StoredRecord>*/ = _this7.sort(items, keys, exact);
        var index = _this7.findMax(sorted, key, value);
        if (index === -1) {
          return [];
        }
        var start = condition === KeyRangeCondition.LowerBound ? index : 0;
        var end = !condition || condition === KeyRangeCondition.UpperBound ? index + 1 : sorted.length;
        var deleted /*: Array<StoredRecordId>*/ = sorted.splice(start, end).map(function (item) {
          return keys.length === 1 ? item[key] : keys.map(function (k) {
            return item[k];
          });
        });
        quick_storage.stores[storeName] = sorted;
        return deleted;
      });
    }

    /**
     * Trim the store from the left by specified length
     */
  }, {
    key: "trimItems",
    value: function trimItems(storeName /*: ShortStoreName*/, length /*: number*/) /*: Promise<Array<StoredRecordId>>*/{
      var _this8 = this;
      var convertedName = convertStoreName(storeName, Direction.right);
      var options /*: StoreOptions*/ = scheme_map.right[convertedName];
      return this.getAll(storeName).then(function (records /*: Array<Record<string, StoredValue>>*/) {
        return records.length ? records[length - 1] : null;
      }).then(function (record) {
        return record ? _this8.deleteBulk(storeName, record[options.keyPath], KeyRangeCondition.UpperBound) : [];
      });
    }

    /**
     * Count the number of records in the store
     */
  }, {
    key: "count",
    value: function count(storeName /*: ShortStoreName*/) /*: Promise<number>*/{
      return this.open().then(function (open) {
        if (open.status === 'error') {
          return localstorage_Promise.reject(open.error);
        }
        var records = quick_storage.stores[storeName];
        return localstorage_Promise.resolve(records instanceof Array ? records.length : 1);
      });
    }

    /**
     * Clear all records from a particular store
     */
  }, {
    key: "clear",
    value: function clear(storeName /*: ShortStoreName*/) /*: Promise<void>*/{
      return this.open().then(function (open) {
        if (open.status === 'error') {
          return localstorage_Promise.reject(open.error);
        }
        return new localstorage_Promise(function (resolve) {
          quick_storage.stores[storeName] = [];
          resolve();
        });
      });
    }

    /**
     * Does nothing, it simply matches the common storage interface
     */
  }, {
    key: "destroy",
    value: function destroy() {} // eslint-disable-line

    /**
     * Does nothing, it simply matches the common storage interface
     */
  }, {
    key: "deleteDatabase",
    value: function deleteDatabase() {} // eslint-disable-line
  }], [{
    key: "isSupported",
    value:
    /**
     * Cached promise of LocalStorage validation
     */

    /**
     * Check if LocalStorage is supported in the current browser
     */
    function isSupported() /*: Promise<boolean>*/{
      if (LocalStorageWrapper.isSupportedPromise) {
        return LocalStorageWrapper.isSupportedPromise;
      } else {
        LocalStorageWrapper.isSupportedPromise = new localstorage_Promise(function (resolve /*: (value: boolean) => void*/) {
          var supported = isLocalStorageSupported();
          if (!supported) {
            sdk_logger.warn('LocalStorage is not supported in this browser');
          }
          resolve(supported);
        });
      }
      return LocalStorageWrapper.isSupportedPromise;
    }
  }]);
  return LocalStorageWrapper;
}();
_defineProperty(LocalStorageWrapper, "isSupportedPromise", null);

;// CONCATENATED MODULE: ./src/sdk/storage/storage.ts


var storage_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;







var StorageType;
(function (StorageType) {
  StorageType[StorageType["noStorage"] = STORAGE_TYPES.NO_STORAGE] = "noStorage";
  StorageType[StorageType["indexedDB"] = STORAGE_TYPES.INDEXED_DB] = "indexedDB";
  StorageType[StorageType["localStorage"] = STORAGE_TYPES.LOCAL_STORAGE] = "localStorage";
})(StorageType || (StorageType = {}));
/**
 * Methods to extend
 */
var _methods /*: CommonStorageMethods*/ = {
  getAll: _getAll,
  getFirst: _getFirst,
  getItem: _getItem,
  filterBy: _filterBy,
  addItem: _addItem,
  addBulk: _addBulk,
  updateItem: _updateItem,
  deleteItem: _deleteItem,
  deleteBulk: _deleteBulk,
  trimItems: _trimItems,
  count: _count,
  clear: _clear,
  destroy: _destroy,
  deleteDatabase: _deleteDatabase
};

/**
 * Extends storage's getAll method by decoding returned records
 */
function _getAll(storage /*: IStorage*/, storeName /*: ShortStoreName*/, firstOnly /*: boolean*/) {
  return storage.getAll(storeName, firstOnly).then(function (records) {
    return convertRecords(storeName, Direction.right, records);
  });
}

/**
 * Extends storage's getFirst method by decoding returned record
 */
function _getFirst(storage /*: IStorage*/, storeName /*: ShortStoreName*/) {
  return storage.getFirst(storeName).then(function (record) {
    return convertRecord(storeName, Direction.right, record);
  });
}

/**
 * Extends storage's getItem method by encoding target value and then decoding returned record
 */
function _getItem(storage /*: IStorage*/, storeName /*: ShortStoreName*/, target /*: StoredRecordId*/) {
  return storage.getItem(storeName, convertValues(storeName, Direction.left, target)).then(function (record) {
    return convertRecord(storeName, Direction.right, record);
  }).catch(function (error) {
    return storage_Promise.reject(decodeErrorMessage(storeName, error));
  });
}

/**
 * Extends storage's filterBy method by encoding target value and then decoding returned records
 */
function _filterBy(storage /*: IStorage*/, storeName /*: ShortStoreName*/, target /*: string*/) {
  return storage.filterBy(storeName, encodeValue(target)).then(function (records) {
    return convertRecords(storeName, Direction.right, records);
  });
}

/**
 * Extends storage's addItem method by encoding target record and then decoding returned keys
 */
function _addItem(storage /*: IStorage*/, storeName /*: ShortStoreName*/, record /*: StoredRecord*/) {
  var convertedRecord = convertRecord(storeName, Direction.left, record);
  return storage.addItem(storeName, convertedRecord).then(function (target) {
    return convertValues(storeName, Direction.right, target);
  }).catch(function (error) {
    return storage_Promise.reject(decodeErrorMessage(storeName, error));
  });
}

/**
 * Extends storage's addBulk method by encoding target records and then decoding returned keys
 */
function _addBulk(storage /*: IStorage*/, storeName /*: ShortStoreName*/, records /*: Array<StoredRecord>*/, overwrite /*: boolean*/) {
  var convertedRecords /*: Array<StoredRecord>*/ = convertRecords(storeName, Direction.left, records);
  return storage.addBulk(storeName, convertedRecords, overwrite).then(function (values) {
    return values.map(function (target) {
      return convertValues(storeName, Direction.right, target);
    });
  }).catch(function (error) {
    return storage_Promise.reject(decodeErrorMessage(storeName, error));
  });
}

/**
 * Extends storage's updateItem method by encoding target record and then decoding returned keys
 */
function _updateItem(storage /*: IStorage*/, storeName /*: ShortStoreName*/, record /*: StoredRecord*/) {
  var convertedRecord = convertRecord(storeName, Direction.left, record);
  return storage.updateItem(storeName, convertedRecord).then(function (target) {
    return convertValues(storeName, Direction.right, target);
  });
}

/**
 * Extends storage's deleteItem method by encoding target value and then decoding returned keys
 */
function _deleteItem(storage /*: IStorage*/, storeName /*: ShortStoreName*/, target /*: StoredRecordId*/) {
  return storage.deleteItem(storeName, convertValues(storeName, Direction.left, target)).then(function (target) {
    return convertValues(storeName, Direction.right, target);
  });
}

/**
 * Extends storage's deleteBulk method by encoding target value and then decoding returned records that are deleted
 */
function _deleteBulk(storage /*: IStorage*/, storeName /*: ShortStoreName*/, value /*: StoredValue*/, condition /*: KeyRangeCondition*/) {
  return storage.deleteBulk(storeName, encodeValue(value), condition).then(function (records) {
    return records.map(function (record) {
      return convertValues(storeName, Direction.right, record);
    });
  });
}

/**
 * Extends storage's trimItems method by passing encoded storage name
 */
function _trimItems(storage /*: IStorage*/, storeName /*: ShortStoreName*/, length /*: number*/) {
  return storage.trimItems(storeName, length);
}

/**
 * Extends storage's count method by passing encoded storage name
 */
function _count(storage /*: IStorage*/, storeName /*: ShortStoreName*/) {
  return storage.count(storeName);
}

/**
 * Extends storage's clear method by passing encoded storage name
 */
function _clear(storage /*: IStorage*/, storeName /*: ShortStoreName*/) {
  return storage.clear(storeName);
}

/**
 * Calls storage's destroy method
 */
function _destroy(storage /*: IStorage*/) {
  return storage.destroy();
}

/**
 * Calls storage's deleteDatabase method
 */
function _deleteDatabase(storage /*: IndexedDB | LocalStorage*/) {
  return storage.deleteDatabase();
}

/**
 * Augment whitelisted methods with encoding/decoding functionality
 */
function _augment() /*: StorageMethods*/{
  var methods /*: Array<[MethodName, StorageMethod]>*/ = entries(_methods).map(function (_ref /*:: */) {
    var _ref2 = _slicedToArray(_ref /*:: */, 2),
      methodName = _ref2[0],
      method = _ref2[1];
    var augmentedMethod /*: StorageMethod*/ = function augmentedMethod /*: StorageMethod*/(storeName /*: StoreName*/) {
      for (var _len = arguments.length, args = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
        args[_key - 1] = arguments[_key];
      }
      return storage_init().then(function (_ref3) {
        var storage = _ref3.storage;
        if (storage) {
          return method.call.apply(method, [null, storage, convertStoreName(storeName, Direction.left)].concat(args));
        }
      });
    };
    return [methodName, augmentedMethod];
  });
  return methods.reduce(reducer, {});
}

/**
 * Type of available storage
 */
var type /*: StorageType*/;

/**
 * Returns type of used storage which is one of possible values INDEXED_DB, LOCAL_STORAGE or NO_STORAGE if there is no
 * storage available
 */
function getType() /*: StorageType*/{
  return type;
}

/**
 * Cached promise of Storage initialization
 */
var _initializationPromise /*: Nullable<Promise<Storage>>*/ = null;

/**
 * Check which storage is available and pick it up
 * Prefer indexedDB over localStorage
 */
function storage_init(dbName /*: string*/) /*: Promise<Storage>*/{
  var storage /*: Nullable<IStorage>*/ = null;
  if (_initializationPromise !== null) {
    return _initializationPromise;
  } else {
    _initializationPromise = storage_Promise.all([IndexedDBWrapper.isSupported(), LocalStorageWrapper.isSupported()]).then(function (_ref4) {
      var _ref5 = _slicedToArray(_ref4, 2),
        idbSupported = _ref5[0],
        lsSupported = _ref5[1];
      quick_storage.setCustomName(dbName);
      if (idbSupported) {
        type = StorageType.indexedDB;
        var idb = new IndexedDBWrapper();
        return idb.setCustomName(dbName).then(function () {
          return storage = idb;
        });
      } else if (lsSupported) {
        type = StorageType.localStorage;
        storage = new LocalStorageWrapper();
        return storage_Promise.resolve(storage);
      } else {
        sdk_logger.error('There is no storage available, app will run with minimum set of features');
        type = StorageType.noStorage;
        storage = null;
        return storage_Promise.resolve(storage);
      }
    }).then(function () {
      return {
        type: type,
        storage: storage
      };
    });
  }
  return _initializationPromise;
}
/* harmony default export */ const storage = (_objectSpread2({
  init: storage_init,
  getType: getType
}, _augment()));
;// CONCATENATED MODULE: ./src/sdk/constants-configs.js



var ConstantsConfig = /*#__PURE__*/function () {
  // Static properties

  // second

  function ConstantsConfig() {
    var data = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    _classCallCheck(this, ConstantsConfig);
    console.log('API Response test:', data.events);
    ConstantsConfig.app_settings = data.app_settings || ConstantsConfig.app_settings;
    ConstantsConfig.events = data.events || ConstantsConfig.events;
    ConstantsConfig.sessions = data.sessions || ConstantsConfig.sessions;
    ConstantsConfig.sdk_clicks = data.sdk_clicks || ConstantsConfig.sdk_clicks;
    ConstantsConfig.sdk_infos = data.sdk_infos || ConstantsConfig.sdk_infos;
    ConstantsConfig.attributions = data.attributions || ConstantsConfig.attributions;
    ConstantsConfig.pkg_info = data.pkg_info || ConstantsConfig.pkg_info;
    ConstantsConfig.base_url = data.base_url || ConstantsConfig.base_url;
    ConstantsConfig.success = data.success || ConstantsConfig.success;
    ConstantsConfig.sdk_enabled = data.sdk_enabled !== undefined ? data.sdk_enabled : ConstantsConfig.sdk_enabled;
    ConstantsConfig.sentry_enabled = data.sentry_enabled !== undefined ? data.sentry_enabled : ConstantsConfig.sentry_enabled;
    ConstantsConfig.session_interval = data.session_interval || ConstantsConfig.session_interval;
    ConstantsConfig.sdk_update = data.sdk_update !== undefined ? data.sdk_update : ConstantsConfig.sdk_update;
    ConstantsConfig.force_update = data.force_update !== undefined ? data.force_update : ConstantsConfig.force_update;
  }

  // Method to display the current configuration (for debugging or logs)
  _createClass(ConstantsConfig, null, [{
    key: "logConfig",
    value: function logConfig() {
      console.log(JSON.stringify(ConstantsConfig, null, 2));
    }
  }]);
  return ConstantsConfig;
}();
_defineProperty(ConstantsConfig, "events", '/api/v1/events');
_defineProperty(ConstantsConfig, "sessions", '/api/v1/sessions');
_defineProperty(ConstantsConfig, "sdk_clicks", '/api/v1/sdk_clicks');
_defineProperty(ConstantsConfig, "sdk_infos", '/api/v1/sdk_infos');
_defineProperty(ConstantsConfig, "attributions", '/api/v1/attributions');
_defineProperty(ConstantsConfig, "pkg_info", '/api/v1/package-info');
_defineProperty(ConstantsConfig, "base_url", 'https://core.wisetrack.io');
_defineProperty(ConstantsConfig, "page", '/api/v1/pages');
_defineProperty(ConstantsConfig, "success", false);
_defineProperty(ConstantsConfig, "message", null);
_defineProperty(ConstantsConfig, "error_code", null);
_defineProperty(ConstantsConfig, "sdk_secure", true);
_defineProperty(ConstantsConfig, "app_settings", '/api/v1/app_settings');
_defineProperty(ConstantsConfig, "sdk_enabled", false);
_defineProperty(ConstantsConfig, "sentry_enabled", true);
_defineProperty(ConstantsConfig, "session_interval", '1800');
_defineProperty(ConstantsConfig, "sdk_update", false);
_defineProperty(ConstantsConfig, "force_update", false);
_defineProperty(ConstantsConfig, "app_settings_enabled", false);
_defineProperty(ConstantsConfig, "sdk_version", '0.9.0-alpha');
_defineProperty(ConstantsConfig, "CONFIG_API_HTTP_ERROR_STATUS", false);
_defineProperty(ConstantsConfig, "HTTP_STATUS_CODE", 200);
/* harmony default export */ const constants_configs = (ConstantsConfig);
;// CONCATENATED MODULE: ./src/sdk/default-params.js


var default_params_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type NavigatorT, type CreatedAtT, type UpdatedAtT, type WebUuidT, type TrackEnabledT, type PlatformT, type LanguageT, type MachineTypeT, type QueueSizeT, type DefaultParamsT } from './types';*/





/**
 * Get created at timestamp
 *
 * @returns {{createdAt: string}}
 * @private
 */
function _getCreatedAt() /*: CreatedAtT*/{
  return {
    createdAt: getTimestamp()
  };
}

/**
 * Get sent at timestamp
 *
 * @returns {{updatedAtT: string}}
 * @private
 */
function _getupdatedAtT() /*: UpdatedAtT*/{
  return {
    updatedAt: getTimestamp()
  };
}

/**
 * Read uuid from the activity state
 *
 * @returns {{webUuid: string}}
 * @private
 */
function _getWebUuid() /*: WebUuidT*/{
  return {
    androidUuid: activity_state.current.uuid
  };
}

/**
 * Get track enabled parameter by reading doNotTrack
 *
 * @returns {{trackingEnabled: boolean}|null}
 * @private
 */
function _getTrackEnabled() /*: ?TrackEnabledT*/{
  var navigatorExt = (navigator /*: NavigatorT*/);
  var isNavigatorDNT = typeof navigatorExt.doNotTrack !== 'undefined';
  var isWindowDNT = typeof window.doNotTrack !== 'undefined';
  var isMsDNT = typeof navigatorExt.msDoNotTrack !== 'undefined';
  var dnt = isNavigatorDNT ? navigatorExt.doNotTrack : isWindowDNT ? window.doNotTrack : isMsDNT ? navigatorExt.msDoNotTrack : null;
  if (parseInt(dnt, 10) === 0 || dnt === 'no') {
    return {
      trackingEnabled: true
    };
  }
  if (parseInt(dnt, 10) === 1 || dnt === 'yes') {
    return {
      trackingEnabled: false
    };
  }
  return null;
}

/**
 * Get platform parameter => hardcoded to `web`
 *
 * @returns {{platform: string}}
 * @private
 */
function _getPlatform() /*: PlatformT*/{
  return {
    initiatedBy: 'web',
    initiatedVersion: constants_configs.sdk_version
  };
}
function _getNeedsResponseDetails() /*: NeedsResponseDetailsT*/{
  return {
    needsResponseDetails: '0'
  };
}
function _getReferrer() /*: ReferrerParamsT*/{
  var result = localStorage.getItem('referrer_key');
  if (result === null || result === undefined || result === 'undefined') {
    result = 'utm_source=other&utm_medium=organic';
  }
  return {
    referrer: result
  };
}

/**
 * Get language preferences
 *
 * @returns {{language: string, country: string|undefined}}
 * @private
 */
function _getLanguage() /*: LanguageT*/{
  var navigatorExt = (navigator /*: NavigatorT*/);
  var _split = (navigatorExt.language || navigatorExt.userLanguage || 'en').split('-'),
    _split2 = _slicedToArray(_split, 2),
    language = _split2[0],
    country = _split2[1];
  return {
    language: language,
    country: country ? '' + country.toLowerCase() : undefined
  };
}

/**
 * Get machine type from navigator.platform property
 *
 * @returns {{machineType: (string|undefined)}}
 */
function _getMachineType() /*: MachineTypeT*/{
  var ua = navigator.userAgent || navigator.vendor;
  var overrideWin32 = navigator.platform === 'Win32' && (ua.indexOf('WOW64') !== -1 || ua.indexOf('Win64') !== -1);
  return {
    machineType: overrideWin32 ? 'Win64' : navigator.platform
  };
}

/**
 * Get the current queue size
 *
 * @returns {Promise}
 * @private
 */
function _getQueueSize() /*: Promise<QueueSizeT>*/{
  return storage.getAll('queue').then(function (records) {
    return {
      queueSize: records.length
    };
  });
}
function defaultParams() /*: Promise<DefaultParamsT>*/{
  return _getQueueSize().then(function (queueSize) {
    return _objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2({}, _getCreatedAt()), _getupdatedAtT()), _getWebUuid()), _getTrackEnabled()), _getPlatform()), _getNeedsResponseDetails()), _getReferrer()), _getLanguage()), _getMachineType()), queueSize);
  });
}
;// CONCATENATED MODULE: ./src/sdk/device_infos.js


var cryptoJS = __webpack_require__(1354);
var UAParser = __webpack_require__(5181);

// Create a new UAParser instance
var parser = new UAParser();

// Function to categorize screen density based on devicePixelRatio
function getScreenDensity() {
  var density = window.devicePixelRatio;
  if (density < 1.5) {
    return 'Low';
  } else if (density >= 1.5 && density <= 2) {
    return 'Medium';
  } else if (density > 2 && density <= 3) {
    return 'High';
  } else {
    return 'Very High';
  }
}
function getDisplaySizeInches() {
  var screenWidth = window.screen.width;
  var screenHeight = window.screen.height;
  var pixelRatio = window.devicePixelRatio;
  var diagonalPixels = Math.sqrt(screenWidth * screenWidth + screenHeight * screenHeight);
  var diagonalInches = diagonalPixels / pixelRatio / 96;
  return diagonalInches.toFixed(2);
}
function getOSArch() {
  var userAgent = navigator.userAgent;
  var platform = navigator.platform;
  if (platform.includes('Win')) {
    if (userAgent.includes('WOW64') || userAgent.includes('Win64')) {
      return '64-bit (Windows)';
    } else {
      return '32-bit (Windows)';
    }
  } else if (platform.includes('Mac')) {
    if (userAgent.includes('Intel') && userAgent.includes('Mac OS X')) {
      return '64-bit (macOS)';
    } else {
      return '32-bit (macOS)';
    }
  } else if (platform.includes('Linux')) {
    if (userAgent.includes('x86_64')) {
      return '64-bit (Linux)';
    } else if (userAgent.includes('i686') || userAgent.includes('i386')) {
      return '32-bit (Linux)';
    } else {
      return 'Unknown Linux architecture';
    }
  } else if (platform.includes('Android')) {
    return 'Unknown (Android)';
  } else if (platform.includes('iPhone') || platform.includes('iPad')) {
    return 'Unknown (iOS)';
  } else {
    return 'Unknown architecture';
  }
}
function getScreenFormat() {
  var screenWidth = window.screen.width;
  var screenHeight = window.screen.height;
  var ppi = 160;
  var screenDiagonalPixels = Math.sqrt(Math.pow(screenWidth, 2) + Math.pow(screenHeight, 2));
  var screenDiagonalInches = screenDiagonalPixels / ppi;
  var aspectRatio = screenWidth / screenHeight;
  var ratio = screenDiagonalInches / aspectRatio;
  var screenFormat = ratio > 7 ? 'long' : 'normal';
  return screenFormat;
}
function getUIMode() {
  var userAgent = navigator.userAgent.toLowerCase();
  if (/mobile/i.test(userAgent)) {
    return 2;
  }
  if (/tablet/i.test(userAgent) || navigator.userAgent.match(/iPad/i) !== null) {
    return 3;
  }
  if (/tv/i.test(userAgent) || /android tv/i.test(userAgent) || /google tv/i.test(userAgent)) {
    return 4;
  }
  return 1;
}
function getUIStyle() {
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function getScreenType() {
  var hasTouch = navigator.maxTouchPoints && navigator.maxTouchPoints > 0 || window.matchMedia && window.matchMedia('(pointer: coarse)').matches;

  // If touch is supported, return 'touch', otherwise return 'pointer'
  return hasTouch ? 'touch' : 'pointer';
}
function getBrowserName() {
  var userAgent = navigator.userAgent;
  if (userAgent.includes('Chrome') && userAgent.includes('Safari') && !userAgent.includes('Edge')) {
    return 'Google Chrome'; // Chrome should be detected before Safari
  } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
    return 'Apple Safari';
  } else if (userAgent.includes('Firefox')) {
    return 'Mozilla Firefox';
  } else if (userAgent.includes('Edge')) {
    return 'Microsoft Edge';
  } else if (userAgent.includes('Trident') || userAgent.includes('MSIE')) {
    return 'Internet Explorer';
  } else if (userAgent.includes('Opera') || userAgent.includes('OPR')) {
    return 'Opera';
  } else if (userAgent.includes('Brave')) {
    return 'Brave Browser';
  } else if (userAgent.includes('Vivaldi')) {
    return 'Vivaldi';
  } else if (userAgent.includes('SamsungBrowser')) {
    return 'Samsung Internet';
  } else if (userAgent.includes('UCBrowser')) {
    return 'UC Browser';
  } else if (userAgent.includes('QQBrowser')) {
    return 'QQ Browser';
  } else if (userAgent.includes('Yandex')) {
    return 'Yandex Browser';
  } else if (userAgent.includes('PaleMoon')) {
    return 'Pale Moon';
  } else if (userAgent.includes('Maxthon')) {
    return 'Maxthon';
  } else if (userAgent.includes('Midori')) {
    return 'Midori Browser';
  } else if (userAgent.includes('Epic')) {
    return 'Epic Browser';
  } else {
    return 'Unknown Browser';
  }
}
function getCpuArchitecture() {
  var platform = navigator.platform.toLowerCase();
  var userAgent = navigator.userAgent.toLowerCase();

  // Check for ARM-based devices
  if (userAgent.includes('arm') || platform.includes('arm')) {
    return 'ARM'; // ARM-based devices, common for mobile and tablets
  }

  // Check for x86 and x64 processors
  if (userAgent.includes('x86') || userAgent.includes('win32') || userAgent.includes('ia32')) {
    return 'x86'; // x86 32-bit
  }

  if (userAgent.includes('x64') || userAgent.includes('amd64')) {
    return 'x64'; // x64 64-bit
  }

  // Detect macOS
  if (platform.includes('mac')) {
    // Older Macs might use PowerPC, but now it's almost exclusively Intel or ARM
    if (userAgent.includes('arm64') || userAgent.includes('aarch64')) {
      return 'ARM'; // ARM-based Macs (e.g., Apple M1/M2)
    }

    return 'x86'; // Intel-based Macs
  }

  // Detect Linux
  if (platform.includes('linux')) {
    if (userAgent.includes('arm') || platform.includes('arm')) {
      return 'ARM'; // ARM-based Linux devices
    }

    return 'x86'; // x86 Linux (may include x86_64)
  }

  // Fallback
  return 'Unknown'; // In case it doesn't match any known pattern
}

function getOSName() {
  var userAgent = navigator.userAgent;

  // For Windows
  if (userAgent.includes('Win')) {
    if (userAgent.includes('Windows NT 10.0')) return 'Windows 10';
    if (userAgent.includes('Windows NT 6.2')) return 'Windows 8';
    if (userAgent.includes('Windows NT 6.1')) return 'Windows 7';
    if (userAgent.includes('Windows NT 6.0')) return 'Windows Vista';
    if (userAgent.includes('Windows NT 5.1')) return 'Windows XP';
    return 'Windows';
  }

  // For macOS
  if (userAgent.includes('Mac')) {
    return 'macOS';
  }

  // For Linux
  if (userAgent.includes('Linux')) {
    return 'Linux';
  }

  // For iOS
  if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
    return 'iOS';
  }

  // For Android
  if (userAgent.includes('Android')) {
    return 'Android';
  }

  // For Chrome OS
  if (userAgent.includes('CrOS')) {
    return 'Chrome OS';
  }

  // For other OS (or unknown)
  return 'Unknown OS';
}
function getWebEngine() {
  var userAgent = navigator.userAgent;
  var engine = 'Unknown Engine';

  // Check for specific engines based on the userAgent string
  if (userAgent.indexOf('Chrome') > -1 || userAgent.indexOf('Chromium') > -1) {
    engine = 'Blink';
  } else if (userAgent.indexOf('Firefox') > -1) {
    engine = 'Gecko';
  } else if (userAgent.indexOf('Safari') > -1 && userAgent.indexOf('Chrome') === -1) {
    engine = 'WebKit';
  } else if (userAgent.indexOf('Edge') > -1) {
    engine = 'Blink'; // Edge is now Chromium-based
  } else if (userAgent.indexOf('Trident') > -1 || userAgent.indexOf('MSIE') > -1) {
    engine = 'Trident'; // Internet Explorer uses the Trident engine
  }

  return engine;
}
function getBrowserVersion() {
  var userAgent = navigator.userAgent;
  var version = 'Unknown Version';

  // Google Chrome (excluding Edge)
  if (userAgent.includes('Chrome') && !userAgent.includes('Edg') && !userAgent.includes('Chromium')) {
    version = userAgent.match(/Chrome\/([0-9.]+)/)[1];
  }
  // Microsoft Edge
  else if (userAgent.includes('Edg')) {
    version = userAgent.match(/Edg\/([0-9.]+)/)[1];
  }
  // Mozilla Firefox
  else if (userAgent.includes('Firefox')) {
    version = userAgent.match(/Firefox\/([0-9.]+)/)[1];
  }
  // Apple Safari (excluding Chrome)
  else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
    version = userAgent.match(/Version\/([0-9.]+)/)[1];
  }
  // Opera (includes both Opera and Chromium-based Opera)
  else if (userAgent.includes('Opera') || userAgent.includes('OPR')) {
    version = userAgent.match(/OPR\/([0-9.]+)/)[1];
  }
  // Internet Explorer
  else if (userAgent.includes('Trident') || userAgent.includes('MSIE')) {
    version = userAgent.match(/(MSIE\s|rv:)([0-9.]+)/)[2];
  }
  // Brave Browser
  else if (userAgent.includes('Brave')) {
    version = userAgent.match(/Brave\/([0-9.]+)/) ? userAgent.match(/Brave\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Vivaldi Browser
  else if (userAgent.includes('Vivaldi')) {
    version = userAgent.match(/Vivaldi\/([0-9.]+)/) ? userAgent.match(/Vivaldi\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Samsung Internet
  else if (userAgent.includes('SamsungBrowser')) {
    version = userAgent.match(/SamsungBrowser\/([0-9.]+)/) ? userAgent.match(/SamsungBrowser\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // UC Browser
  else if (userAgent.includes('UCBrowser')) {
    version = userAgent.match(/UCBrowser\/([0-9.]+)/) ? userAgent.match(/UCBrowser\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // QQ Browser
  else if (userAgent.includes('QQBrowser')) {
    version = userAgent.match(/QQBrowser\/([0-9.]+)/) ? userAgent.match(/QQBrowser\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Yandex Browser
  else if (userAgent.includes('YaBrowser')) {
    version = userAgent.match(/YaBrowser\/([0-9.]+)/) ? userAgent.match(/YaBrowser\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Pale Moon
  else if (userAgent.includes('PaleMoon')) {
    version = userAgent.match(/PaleMoon\/([0-9.]+)/) ? userAgent.match(/PaleMoon\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Maxthon
  else if (userAgent.includes('Maxthon')) {
    version = userAgent.match(/Maxthon\/([0-9.]+)/) ? userAgent.match(/Maxthon\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Midori
  else if (userAgent.includes('Midori')) {
    version = userAgent.match(/Midori\/([0-9.]+)/) ? userAgent.match(/Midori\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  // Epic Browser
  else if (userAgent.includes('Epic')) {
    version = userAgent.match(/Epic\/([0-9.]+)/) ? userAgent.match(/Epic\/([0-9.]+)/)[1] : 'Unknown Version';
  }
  return version;
}
function getIndexedDBSupport() {
  return 'indexedDB' in window;
}
function getSessionStorageStatus() {
  return typeof Storage !== 'undefined' && sessionStorage !== null;
}
function getLocalStorageStatus() {
  return typeof Storage !== 'undefined' && localStorage !== null;
}
function getSessionStorageSize() {
  var totalSize = 0;

  // Iterate over all items in sessionStorage
  for (var i = 0; i < sessionStorage.length; i++) {
    var key = sessionStorage.key(i);
    var value = sessionStorage.getItem(key);

    // Convert the value to a string and calculate its size in bytes
    totalSize += key.length + value.length;
  }

  // Return the size in bytes
  return totalSize;
}
function getLocalStorageSize() {
  var totalSize = 0;

  // Iterate over all items in localStorage
  for (var i = 0; i < localStorage.length; i++) {
    var key = localStorage.key(i);
    var value = localStorage.getItem(key);

    // Calculate the size of each key and value
    totalSize += key.length + value.length;
  }

  // Return the total size in bytes
  return totalSize;
}
function getWebGLSupport() {
  try {
    var canvas = document.createElement('canvas');
    return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
  } catch (e) {
    return false;
  }
}
function getDeviceType() {
  var userAgent = navigator.userAgent.toLowerCase();

  // Detect mobile phones (Android/iOS)
  if (/iphone|ipod|android.*mobile|windows phone/.test(userAgent)) {
    return 'mobile';
  }

  // Detect tablets (iPad, Android tablets, etc.)
  if (/ipad|android(?!.*mobile)/.test(userAgent)) {
    return 'tablet';
  }

  // Detect TVs (based on user agent keywords)
  if (/smart-tv|hdtv|appletv|google tv|roku|amazon fire tv/.test(userAgent)) {
    return 'tv';
  }

  // Detect PCs (this will catch most desktop/laptop devices)
  if (/windows|macintosh|linux/.test(userAgent)) {
    return 'desktop';
  }

  // Default fallback if the device type cannot be determined
  return 'Unknown';
}

// Function to get the outer width of the window
function getWindowOuterWidth() {
  return window.outerWidth;
}

// Function to get the outer height of the window
function getWindowOuterHeight() {
  return window.outerHeight;
}

// Function to get the display width (screen width)
function getDisplayWidth() {
  return screen.width;
}

// Function to get the display height (screen height)
function getDisplayHeight() {
  return screen.height;
}
function getWebGLFingerprintHash() {
  var canvas = document.createElement('canvas');
  var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (!gl) {
    return null;
  }
  var renderer = gl.getParameter(gl.RENDERER);
  var vendor = gl.getParameter(gl.VENDOR);
  var version = gl.getParameter(gl.VERSION);
  var shadingLanguageVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
  var maxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE);
  var maxVertexAttributes = gl.getParameter(gl.MAX_VERTEX_ATTRIBS);
  var maxRenderbufferSize = gl.getParameter(gl.MAX_RENDERBUFFER_SIZE);
  var extensions = gl.getSupportedExtensions().join(', ');
  var fingerprintData = "".concat(renderer, "|").concat(vendor, "|").concat(version, "|").concat(shadingLanguageVersion, "|").concat(maxTextureSize, "|").concat(maxVertexAttributes, "|").concat(maxRenderbufferSize, "|").concat(extensions);
  var hash = cryptoJS.SHA256(fingerprintData).toString();
  return hash;
}
function getCpuLpc() {
  // Returns the number of logical processor cores (CPU threads)
  return navigator.hardwareConcurrency || 'Not Available';
}
function getUserAgent() {
  return navigator.userAgent;
}
function getDeviceName() {
  var userAgent = navigator.userAgent;
  parser.setUA(userAgent);
  var result = parser.getResult();
  var deviceName = result.device.model || null;
  return deviceName;
}
function getDeviceManufacturer() {
  var userAgent = navigator.userAgent;
  parser.setUA(userAgent);
  var result = parser.getResult();
  var manufacturer = result.device.vendor || null;
  return manufacturer;
}
function getScreenColorDepth() {
  var colorDepth = window.screen.colorDepth;
  if (colorDepth <= 16) {
    return 'low';
  } else if (colorDepth <= 24) {
    return 'medium';
  } else {
    return 'high';
  }
}
function getBrowserInfo() {
  return _getBrowserInfo.apply(this, arguments);
}
function _getBrowserInfo() {
  _getBrowserInfo = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
    var os_name, os_arch, device_type, cpu_type, cpu_lpc, device_name, device_manufacturer, screen_type, ui_mode, ui_style, browser_name, browser_version, browser_platform, session_storage_enabled, session_storage, indexed_db_enabled, local_storage_enabled, local_storage, web_gl_support, web_gl_fingerprint, wout_width, wout_height, display_width, display_height, screen_density, screen_size, display_size, web_engine, user_agent, screen_format;
    return _regeneratorRuntime().wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            os_name = getOSName();
            os_arch = getOSArch(); // Detect 32-bit or 64-bit OS
            device_type = getDeviceType();
            cpu_type = getCpuArchitecture();
            cpu_lpc = getCpuLpc();
            device_name = getDeviceName();
            device_manufacturer = getDeviceManufacturer();
            screen_type = getScreenType();
            ui_mode = getUIMode();
            ui_style = getUIStyle();
            browser_name = getBrowserName();
            browser_version = getBrowserVersion();
            browser_platform = navigator.platform;
            session_storage_enabled = getSessionStorageStatus();
            session_storage = getSessionStorageSize();
            indexed_db_enabled = getIndexedDBSupport();
            local_storage_enabled = getLocalStorageStatus();
            local_storage = getLocalStorageSize();
            web_gl_support = getWebGLSupport();
            web_gl_fingerprint = getWebGLFingerprintHash();
            wout_width = getWindowOuterWidth();
            wout_height = getWindowOuterHeight();
            display_width = getDisplayWidth();
            display_height = getDisplayHeight();
            screen_density = getScreenColorDepth();
            screen_size = getScreenDensity(); // Get screen density category
            display_size = getDisplaySizeInches(); // Get screen size in inches
            web_engine = getWebEngine();
            user_agent = getUserAgent();
            screen_format = getScreenFormat();
            return _context.abrupt("return", {
              os_name: os_name,
              os_arch: os_arch,
              // Add the os_arch (32-bit/64-bit) to the returned info
              device_type: device_type,
              cpu_type: cpu_type,
              cpu_lpc: cpu_lpc,
              device_name: device_name,
              device_manufacturer: device_manufacturer,
              screen_type: screen_type,
              browser_version: browser_version,
              browser_name: browser_name,
              browser_platform: browser_platform,
              session_storage_enabled: session_storage_enabled,
              session_storage: session_storage,
              indexed_db_enabled: indexed_db_enabled,
              local_storage_enabled: local_storage_enabled,
              local_storage: local_storage,
              web_gl_support: web_gl_support,
              web_gl_fingerprint: web_gl_fingerprint,
              wout_width: wout_width,
              wout_height: wout_height,
              display_width: display_width,
              display_height: display_height,
              display_size: display_size,
              screen_density: screen_density,
              screen_size: screen_size,
              web_engine: web_engine,
              ui_mode: ui_mode,
              ui_style: ui_style,
              user_agent: user_agent,
              screen_format: screen_format
            });
          case 31:
          case "end":
            return _context.stop();
        }
      }
    }, _callee);
  }));
  return _getBrowserInfo.apply(this, arguments);
}
// EXTERNAL MODULE: ./src/sdk/types.js
var types = __webpack_require__(3807);
;// CONCATENATED MODULE: ./src/sdk/device_params.js

var device_params_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;


function _getOSName() {
  return {
    osName: getOSName()
  };
}
function _getOSArch() {
  return {
    osArch: getOSArch()
  };
}
function _getDeviceType() {
  return {
    deviceType: getDeviceType()
  };
}
function _getCpuArchitecture() {
  return {
    cpuType: getCpuArchitecture()
  };
}
function _getCpuLpc() {
  return {
    cpuLpc: getCpuLpc()
  };
}
function _getDeviceName() {
  return {
    deviceName: getDeviceName()
  };
}
function _getDeviceManufacturer() {
  return {
    deviceManufacturer: getDeviceManufacturer()
  };
}
function _getScreenType() {
  return {
    screenType: getScreenType()
  };
}
function _getUIMode() {
  return {
    uiMode: getUIMode()
  };
}
function _getUIStyle() {
  return {
    uiStyle: getUIStyle()
  };
}
function _getBrowserName() {
  return {
    browserName: getBrowserName()
  };
}
function _getBrowserVersion() {
  return {
    browserVersion: getBrowserVersion()
  };
}
function _getSessionStorageStatus() {
  return {
    sessionStorageEnabled: getSessionStorageStatus()
  };
}
function _getSessionStorageSize() {
  return {
    sessionStorage: getSessionStorageSize()
  };
}
function _getIndexedDBSupport() {
  return {
    indexedDbEnabled: getIndexedDBSupport()
  };
}
function _getLocalStorageStatus() {
  return {
    localStorageEnabled: getLocalStorageStatus()
  };
}
function _getLocalStorageSize() {
  return {
    localStorage: getLocalStorageSize()
  };
}
function _getWebGLSupport() {
  return {
    webGlSupport: getWebGLSupport()
  };
}
function _getWebGLFingerprintHash() {
  return {
    webGlFingerprint: getWebGLFingerprintHash()
  };
}
function _getWindowOuterWidth() {
  return {
    woutWidth: getWindowOuterWidth()
  };
}
function _getWindowOuterHeight() {
  return {
    woutHeight: getWindowOuterHeight()
  };
}
function _getDisplayWidth() {
  return {
    displayWidth: getDisplayWidth()
  };
}
function _getDisplayHeight() {
  return {
    displayHeight: getDisplayHeight()
  };
}
function _getScreenDensity() {
  return {
    screenDensity: getScreenColorDepth()
  };
}
function _getDisplaySize() {
  return {
    displaySize: getDisplaySizeInches() || 'hamded'
  };
}
function _getScreenSizeInches() {
  return {
    screenSize: getScreenDensity()
  };
}
function _getWebEngine() {
  return {
    webEngine: getWebEngine()
  };
}
function _getUserAgent() {
  return {
    webUserAgent: getUserAgent()
  };
}
function _getScreenFormat() {
  return {
    screenFormat: getScreenFormat()
  };
}
function defaultDeviceParams() /*: Promise<DeviceParamsT>*/{
  return _objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2({}, _getOSName()), _getOSArch()), _getDeviceType()), _getCpuArchitecture()), _getCpuLpc()), _getDeviceName()), _getDeviceManufacturer()), _getScreenType()), _getUIMode()), _getUIStyle()), _getBrowserName()), _getBrowserVersion()), _getSessionStorageStatus()), _getSessionStorageSize()), _getIndexedDBSupport()), _getLocalStorageStatus()), _getLocalStorageSize()), _getWebGLSupport()), _getWebGLFingerprintHash()), _getWindowOuterWidth()), _getWindowOuterHeight()), _getDisplayWidth()), _getDisplayHeight()), _getDisplaySize()), _getScreenDensity()), _getScreenSizeInches()), _getWebEngine()), _getUserAgent()), _getScreenFormat());
}
;// CONCATENATED MODULE: ./src/sdk/http.js




var _excluded = ["eventToken", "partnerParams"];
var http_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type UrlT, type DefaultParamsT, type HttpSuccessResponseT, type HttpErrorResponseT, type HttpRequestParamsT, type ErrorCodeT, type DeviceParamsT } from './types';*/









/**
 * Get filtered response from successful request
 *
 * @param {Object} xhr
 * @param {String} url
 * @returns {Object}
 * @private
 */
function _getSuccessResponse(xhr /*: XMLHttpRequest*/, url /*: UrlT*/) /*: HttpSuccessResponseT*/{
  var result = JSON.parse(xhr.responseText);
  var response = {
    status: 'success',
    adid: result.adid,
    timestamp: result.timestamp,
    ask_in: result.ask_in,
    retry_in: result.retry_in,
    continue_in: result.continue_in,
    tracking_state: result.tracking_state,
    attribution: undefined,
    message: undefined
  };
  if (isRequest(url, 'attribution')) {
    response.attribution = result.attribution;
    response.message = result.message;
  }
  return entries(response).filter(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 2),
      value = _ref2[1];
    return !!value;
  }).reduce(reducer, {});
}

/**
 * Get an error object which is about to be passed to resolve or reject method
 *
 * @param {Object} xhr
 * @param {string} code
 * @param {boolean=} proceed
 * @returns {Object}
 * @private
 */
function _getErrorResponse(xhr /*: XMLHttpRequest*/, code /*: ErrorCodeT*/) /*: HttpErrorResponseT*/{
  var proceed /*: boolean*/ = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;
  return {
    status: 'error',
    action: proceed ? 'CONTINUE' : 'RETRY',
    response: isValidJson(xhr.responseText) ? JSON.parse(xhr.responseText) : xhr.responseText,
    message: HTTP_ERRORS[code],
    code: code
  };
}

// /**
//  * Encode parameter depending on the type
//  *
//  * @param {string} key
//  * @param {*} value
//  * @returns {string}
//  * @private
//  */
// function _encodeParam ([key, value]: [string, $Values<ParamsWithAttemptsT>]): string {
//   const encodedKey = encodeURIComponent(key)
//   let encodedValue = value

//   if (typeof value === 'string') {
//     encodedValue = encodeURIComponent(value)
//   }

//   if (isObject(value)) {
//     encodedValue = encodeURIComponent(JSON.stringify(value) || '')
//   }

//   return [encodedKey, encodedValue].join('=')
// }

/**
 * Creates the log key with some spaces appended to it
 *
 * @param {string} header
 * @param {string} str
 * @returns {string}
 * @private
 */
function _logKey(header /*: string*/, str /*: string*/) /*: string*/{
  var spaces = header.slice(0, header.length - str.length - 1).split('').reduce(function (acc) {
    return acc.concat(' ');
  }, '');
  return "".concat(str).concat(spaces, ":");
}
function transformParams(data) {
  if (data.eventToken && _typeof(data.eventToken) === 'object') {
    // If eventToken is an object, extract its properties and merge them into the root object
    var _data$eventToken = data.eventToken,
      eventToken = _data$eventToken.eventToken,
      partnerParams = _data$eventToken.partnerParams,
      eventTokenProps = _objectWithoutProperties(_data$eventToken, _excluded);

    // Convert partnerParams to a string
    var partnerParamsString = partnerParams ? JSON.stringify(partnerParams) : null;
    return _objectSpread2(_objectSpread2(_objectSpread2({}, data), {}, {
      eventToken: eventToken
    }, eventTokenProps), {}, {
      // Merge the other properties (deduplicationId, revenue, currency) into the root object
      partnerParams: partnerParamsString // Convert partnerParams into a string
    });
  } else if (data.eventToken && typeof data.eventToken === 'string') {
    // If eventToken is already a string, return the object as is
    return data;
  }

  // Return the unchanged object if no eventToken found
  return data;
}

/**
 * Encode key-value pairs to be used in url
 *
 * @param {Object} params
 * @param {Object} defaultParams
 * @param {Object} defaultDeviceParams
 * @returns {string}
 * @private
 */
function _encodeParams(params, defaultParams, defaultDeviceParams) {
  var toSnakeCase = function toSnakeCase(key) {
    return key.replace(/([A-Z])/g, function ($1) {
      return "_".concat($1.toLowerCase());
    });
  };
  console.log(params);
  console.log(defaultParams);
  console.log(defaultDeviceParams);
  var dataParams = transformParams(params);
  var allParams = entries(_objectSpread2(_objectSpread2(_objectSpread2(_objectSpread2({}, config.getBaseParams()), defaultParams), dataParams), defaultDeviceParams)).map(function (_ref3) {
    var _ref4 = _slicedToArray(_ref3, 2),
      key = _ref4[0],
      value = _ref4[1];
    return [toSnakeCase(key), value];
  });
  var _needsResponseDetails = allParams.find(function (_ref5) {
    var _ref6 = _slicedToArray(_ref5, 1),
      key = _ref6[0];
    return key === 'needs_response_details';
  });
  var needsResponseDetails = _needsResponseDetails ? _needsResponseDetails[1] : undefined;
  var filteredParams = allParams.filter(function (_ref7) {
    var _ref8 = _slicedToArray(_ref7, 2),
      key = _ref8[0],
      value = _ref8[1];
    return value !== undefined && value !== null && value !== '' && key !== 'needs_response_details';
  });
  var parameters = filteredParams.reduce(function (acc, _ref9) {
    var _ref10 = _slicedToArray(_ref9, 2),
      key = _ref10[0],
      value = _ref10[1];
    acc[key] = value;
    return acc;
  }, {});
  return JSON.stringify({
    needs_response_details: needsResponseDetails !== undefined ? needsResponseDetails : false,
    parameters: parameters
  }, null, 2);
}

/**
 * Handle xhr response from server
 *
 * @param {Function} reject
 * @param {Function} resolve
 * @param {Object} xhr
 * @param {string} url
 * @private
 */
function _handleReadyStateChange(reject, resolve, _ref11 /*:: */) {
  var xhr = _ref11 /*:: */.xhr,
    url = _ref11 /*:: */.url;
  if (xhr.readyState !== 4) {
    return;
  }
  var okStatus = xhr.status >= 200 && xhr.status < 300;
  var validJson = isValidJson(xhr.responseText);
  if (xhr.status === 0) {
    reject(_getErrorResponse(xhr, 'NO_CONNECTION'));
  } else {
    if (validJson) {
      return okStatus ? resolve(_getSuccessResponse(xhr, url)) : resolve(_getErrorResponse(xhr, 'SERVER_CANNOT_PROCESS', true));
    } else {
      return okStatus ? reject(_getErrorResponse(xhr, 'SERVER_MALFORMED_RESPONSE')) : reject(_getErrorResponse(xhr, 'SERVER_INTERNAL_ERROR'));
    }
  }
}

/**
 * Prepare url and params depending on the resource type
 *
 * @param {string} url
 * @param {string} method
 * @param {Object} params
 * @param {Object} defaultParams
 * @returns {{encodedParams: string, fullUrl: string}}
 * @private
 */
function _prepareUrlAndParams(_ref12 /*:: */, defaultParams /*: DefaultParamsT*/, defaultDeviceParams /*: DefaultParamsT*/) /*: { fullUrl: string, encodedParams: string }*/{
  var endpoint = _ref12 /*:: */.endpoint,
    url = _ref12 /*:: */.url,
    method = _ref12 /*:: */.method,
    params = _ref12 /*:: */.params;
  var encodedParams = _encodeParams(params, defaultParams, defaultDeviceParams);
  console.log('request boy: ', encodedParams);
  return {
    fullUrl: endpoint + url + (method === 'GET' ? "?".concat(encodedParams) : ''),
    encodedParams: encodedParams
  };
}

/**
 * Set headers for the xhr object
 *
 * @param {XMLHttpRequest} xhr
 * @param {string} method
 * @private
 */
function _prepareHeaders(xhr /*: XMLHttpRequest*/, method /*: $PropertyType<HttpRequestParamsT, 'method'>*/) /*: void*/{
  var logHeader = 'REQUEST HEADERS:';
  var headers = [['Client-SDK', "js".concat(globals.version)], ['Content-Type', method === 'POST' ? 'application/json' : 'application/x-www-form-urlencoded']];
  sdk_logger.log(logHeader);
  headers.forEach(function (_ref13) {
    var _ref14 = _slicedToArray(_ref13, 2),
      key = _ref14[0],
      value = _ref14[1];
    xhr.setRequestHeader(key, value);
    sdk_logger.log(_logKey(logHeader, key), value);
  });
}

/**
 * Build xhr to perform all kind of api requests
 *
 * @param {string} url
 * @param {string} [method='GET']
 * @param {Object} [params={}]
 * @param {Object} defaultParams
 * @returns {Promise}
 */
function _buildXhr(_ref15 /*:: */, defaultParams /*: DefaultParamsT*/, defaultDeviceParams /*: DeviceParamsT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
  var endpoint = _ref15 /*:: */.endpoint,
    url = _ref15 /*:: */.url,
    _ref15$method = _ref15 /*:: */.method,
    method = _ref15$method === void 0 ? 'GET' : _ref15$method,
    _ref15$params = _ref15 /*:: */.params,
    params = _ref15$params === void 0 ? {} : _ref15$params;
  var _prepareUrlAndParams2 = _prepareUrlAndParams({
      endpoint: endpoint,
      url: url,
      method: method,
      params: params
    }, defaultParams, defaultDeviceParams),
    fullUrl = _prepareUrlAndParams2.fullUrl,
    encodedParams = _prepareUrlAndParams2.encodedParams;
  return new http_Promise(function (resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.open(method, fullUrl, true);
    _prepareHeaders(xhr, method);
    xhr.onreadystatechange = function () {
      return _handleReadyStateChange(reject, resolve, {
        xhr: xhr,
        url: url
      });
    };
    xhr.onerror = function () {
      return reject(_getErrorResponse(xhr, 'TRANSACTION_ERROR'));
    };
    xhr.send(method === 'GET' ? undefined : encodedParams);
  });
}

/**
 * Intercept response from backend
 *
 * @param {Object} result
 * @param {string} result.status
 * @param {string} url
 * @returns {Object}
 * @private
 */
function _interceptResponse(result /*: HttpSuccessResponseT | HttpErrorResponseT*/, url /*: UrlT*/) /*: HttpSuccessResponseT | HttpErrorResponseT*/{
  if (result.status === 'success') {
    return _interceptSuccess(result, url);
  }
  return result;
}

/**
 * Intercept successful response from backend and:
 * - always check if tracking_state is set to `opted_out` and if yes disable sdk
 * - check if ask_in parameter is present in order to check if attribution have been changed
 * - emit session finish event if session request
 *
 * @param {Object} result
 * @param {string} result.tracking_state
 * @param {number} result.ask_in
 * @param {string} url
 * @returns {Object}
 * @private
 */
function _interceptSuccess(result /*: HttpSuccessResponseT*/, url) /*: HttpSuccessResponseT*/{
  var isGdprRequest = isRequest(url, 'gdpr_forget_device');
  var isAttributionRequest = isRequest(url, 'attribution');
  var isSessionRequest = isRequest(url, 'session');
  var isThirdPartySharingOptOutRequest = isRequest(url, 'disable_third_party_sharing');
  var optedOut = result.tracking_state === 'opted_out';
  if (!isGdprRequest && optedOut) {
    publish('sdk:gdpr-forget-me');
    return result;
  }
  if (!isAttributionRequest && !isGdprRequest && !optedOut && result.ask_in) {
    publish('attribution:check', result);
  }
  if (isSessionRequest) {
    publish('session:finished', result);
  }
  if (isThirdPartySharingOptOutRequest) {
    publish('sdk:third-party-sharing-opt-out');
    return result;
  }
  return result;
}

/**
 * Http request factory to perform all kind of api requests
 *
 * @param {Object} options
 * @returns {Promise}
 */
function http(options /*: HttpRequestParamsT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
  var deviceInfosParams = defaultDeviceParams();
  return defaultParams().then(function (defaultParams) {
    return _buildXhr(options, defaultParams, deviceInfosParams);
  }).then(function (result) {
    return _interceptResponse(result, options.url);
  });
}
;// CONCATENATED MODULE: ./src/sdk/backoff.js
/*:: // 
import { type BackOffStrategyT } from './types';*/


/**
 * Options for the back-off strategy for different environments
 *
 * @type {Object}
 */
var _options = {
  long: {
    delay: 2 * MINUTE,
    maxDelay: DAY,
    minRange: 0.5,
    maxRange: 1.0
  },
  short: {
    delay: 200,
    maxDelay: HOUR,
    minRange: 0.5,
    maxRange: 1.0
  },
  test: {
    delay: 100,
    maxDelay: 300
  }
};

/**
 * Get random number in provided range
 *
 * @param {number} min
 * @param {number} max
 * @returns {number}
 * @private
 */
function _randomInRange(min, max) {
  return Math.random() * (max - min) + min;
}

/**
 * Calculate exponential back-off with optional jitter factor applied
 *
 * @param {number} attempts
 * @param {string} strategy
 * @returns {number}
 */
function backOff(attempts /*: number*/, strategy /*: ?BackOffStrategyT*/) /*: number*/{
  strategy = strategy || 'long';
  var options =  false ? 0 : _options[strategy];
  var delay = options.delay * Math.pow(2, attempts - 1);
  delay = Math.min(delay, options.maxDelay);
  if (options.minRange && options.maxRange) {
    delay = delay * _randomInRange(options.minRange, options.maxRange);
  }
  return Math.round(delay);
}
;// CONCATENATED MODULE: ./src/sdk/listeners.js

/*:: // 
import { type DocumentT } from './types';*/

/*:: type EventCbT = (e: Event) => void*/
/*:: type PageVisibilityHiddenAttr = 'hidden' | 'mozHidden' | 'msHidden' | 'oHidden' | 'webkitHidden'*/
/*:: type PageVisibilityEventName = 'visibilitychange' | 'mozvisibilitychange' | 'msvisibilitychange' | 'ovisibilitychange' | 'webkitvisibilitychange'*/
/*:: type PageVisibilityApiMap = {|
  hidden: PageVisibilityHiddenAttr,
  visibilityChange: PageVisibilityEventName
|}*/
var _connected /*: boolean*/ = navigator.onLine;

/**
 * Bind to online and offline events
 */
function register() /*: void*/{
  on(window, 'online', _handleOnline);
  on(window, 'offline', _handleOffline);
}

/**
 * Handle online event, set connected flag to true
 *
 * @private
 */
function _handleOnline() /*: void*/{
  _connected = true;
}

/**
 * Handle offline event, set connected flag to false
 * @private
 */
function _handleOffline() /*: void*/{
  _connected = false;
}

/**
 * Bind event to an element
 *
 * @param {Window|Document} element
 * @param {string} eventName
 * @param {Function} func
 */
function on(element /*: Document | any*/, eventName /*: string*/, func /*: EventCbT*/) /*: void*/{
  if (element.addEventListener) {
    element.addEventListener(eventName, func, false);
  }
}

/**
 * Unbind event off an element
 *
 * @param {Window|Document} element
 * @param {string} eventName
 * @param {Function} func
 */
function off(element /*: Document | any*/, eventName /*: string*/, func /*: EventCbT*/) /*: void*/{
  if (element.removeEventListener) {
    element.removeEventListener(eventName, func, false);
  }
}

/**
 * Get Page Visibility API attributes that can be accessed depending on the browser implementation
 *
 * @returns {{hidden: string, visibilityChange: string}|null}
 * @private
 */
function getVisibilityApiAccess() /*: ?PageVisibilityApiMap*/{
  var documentExt = (document /*: DocumentT*/);
  if (typeof documentExt.hidden !== 'undefined') {
    return {
      hidden: 'hidden',
      visibilityChange: 'visibilitychange'
    };
  }
  var accessMap /*: {[key: PageVisibilityHiddenAttr]: PageVisibilityEventName}*/ = {
    mozHidden: 'mozvisibilitychange',
    msHidden: 'msvisibilitychange',
    oHidden: 'ovisibilitychange',
    webkitHidden: 'webkitvisibilitychange'
  };
  var accessMapEntries = entries(accessMap);
  for (var i = 0; i < accessMapEntries.length; i += 1) {
    var _accessMapEntries$i = _slicedToArray(accessMapEntries[i], 2),
      hidden = _accessMapEntries$i[0],
      visibilityChange = _accessMapEntries$i[1];
    if (typeof documentExt[hidden] !== 'undefined') {
      return {
        hidden: hidden,
        visibilityChange: visibilityChange
      };
    }
  }
  return null;
}

/**
 * Check if connected to internet
 *
 * @returns {boolean}
 */
function isConnected() /*: boolean*/{
  return _connected;
}

/**
 * Unbind from online and offline events
 */
function listeners_destroy() /*: void*/{
  off(window, 'online', _handleOnline);
  off(window, 'offline', _handleOffline);
}

;// CONCATENATED MODULE: ./src/sdk/request.js


var request_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type HttpSuccessResponseT, type HttpErrorResponseT, type HttpContinueCbT, type BackOffStrategyT, type WaitT, type UrlT, type MethodT, type RequestParamsT, type HttpRequestParamsT } from './types';*/







//import { getBaseUrlsIterator, BaseUrlsIterator, BaseUrlsMap } from './url-strategy'

/*:: type RequestConfigT = {|
  url?: UrlT,
    method ?: MethodT,
    params ?: RequestParamsT,
    continueCb ?: HttpContinueCbT,
    strategy ?: BackOffStrategyT,
    wait ?: ? WaitT
      |}*/
/*:: type DefaultConfigT = {|
  url?: UrlT,
    method: MethodT,
      params ?: RequestParamsT,
      continueCb ?: HttpContinueCbT
        |}*/
/*:: type AttemptsT = number*/
/*:: type StartAtT = number*/
var DEFAULT_ATTEMPTS /*: AttemptsT*/ = 0;
var DEFAULT_WAIT /*: WaitT*/ = 150;
var MAX_WAIT /*: WaitT*/ = 0x7FFFFFFF; // 2^31 - 1
var NO_CONNECTION_WAIT = 60 * SECOND;
var request_Request = function Request() {
  var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
    url = _ref.url,
    _ref$method = _ref.method,
    method = _ref$method === void 0 ? 'GET' : _ref$method,
    _ref$params = _ref.params,
    params = _ref$params === void 0 ? {} : _ref$params,
    continueCb = _ref.continueCb,
    strategy = _ref.strategy,
    wait = _ref.wait;
  /**
   * Global param values set on request instantiation and later used for restore
   *
   * @type {{url: string, method: string, params: Object, continueCb: Function}}
   * @private
   */
  var _default /*: DefaultConfigT*/ = {
    url: url,
    method: method,
    params: params,
    continueCb: continueCb
  };

  /**
   * Url param per instance or per request
   *
   * @type {string}
   * @private
   */
  var _url /*: ?UrlT*/ = url;

  /**
   * Method param per instance or per request, defaults to `GET`
   *
   * @type {string}
   * @private
   */
  var _method /*: MethodT*/ = method;

  /**
   * Request params per instance or per request
   *
   * @type {Object}
   * @private
   */
  var _params /*: RequestParamsT*/ = _objectSpread2({}, params);

  /**
   * Optional continue callback per instance or per request
   *
   * @type {Function}
   * @private
   */
  var _continueCb /*: ?HttpContinueCbT*/ = continueCb;

  /**
   * Back-off strategy
   *
   * @type {string|null}
   * @private
   */
  var _strategy /*: ?BackOffStrategyT*/ = strategy;

  /**
   * Url Startegy iterator to go through endpoints to retry to send request
   */
  var _baseUrlsIterator /*: BaseUrlsIterator*/;

  /**
   * Current base urls map to send request
   */
  //let _baseUrlsIteratorCurrent: { value: BaseUrlsMap, done: boolean }

  /**
   * Reset iterator state and get the first endpoint to use it in the next try
   */
  // const _resetBaseUrlsIterator = () => {
  //   _baseUrlsIterator.reset()
  //   _baseUrlsIteratorCurrent = _baseUrlsIterator.next()
  // }

  /**
   * Returns base url depending on request path
   */
  // const _getBaseUrl = (urlsMap: BaseUrlsMap, url: UrlT): string => {
  //   const base = url === '/gdpr_forget_device' ? 'gdpr' : 'app'
  //   return urlsMap[base]
  // }

  /**
   * Timeout id to be used for clearing
   *
   * @type {number|null}
   * @private
   */
  var _timeoutId /*: ?TimeoutID*/ = null;

  /**
   * Number of request and connection attempts
   *
   * @type {{request: number, connection: number}}
   * @private
   */
  var _attempts
  /*: {
      request: AttemptsT,
      connection: AttemptsT
    }*/
  = {
    request: DEFAULT_ATTEMPTS,
    connection: DEFAULT_ATTEMPTS
  };

  /**
   * Waiting time for the request to be sent
   *
   * @type {number}
   * @private
   */
  var _wait /*: WaitT*/ = _prepareWait(wait);

  /**
   * Timestamp when the request has been scheduled
   *
   * @type {Date|null}
   * @private
   */
  var _startAt /*: ?StartAtT*/ = null;

  /**
   * Ensure that wait is not more than maximum 32int so it does not cause overflow in setTimeout
   *
   * @param {number} wait
   * @returns {number}
   * @private
   */
  function _prepareWait(wait /*: ?WaitT*/) /*: WaitT*/{
    wait = wait || DEFAULT_WAIT;
    return wait > MAX_WAIT ? MAX_WAIT : wait;
  }

  /**
   * Override current parameters if available
   *
   * @param {string=} url
   * @param {string=} method
   * @param {Object=} params
   * @param {Function=} continueCb
   * @private
   */
  function _prepareParams(_ref2 /*:: */) /*: void*/{
    var url = _ref2 /*:: */.url,
      method = _ref2 /*:: */.method,
      params = _ref2 /*:: */.params,
      continueCb = _ref2 /*:: */.continueCb;
    if (url) {
      _url = url;
    }
    if (method) {
      _method = method;
    }
    if (!isEmpty(params)) {
      _params = _objectSpread2({}, params);
    }
    _params = _objectSpread2({
      createdAt: getTimestamp()
    }, _params);
    if (typeof continueCb === 'function') {
      _continueCb = continueCb;
    }
  }

  /**
   * Clear previous attempt if new one is about to happen faster
   *
   * @param {number} wait
   * @returns {boolean}
   * @private
   */
  function _skip(wait /*: ?WaitT*/) /*: boolean*/{
    if (!_startAt) {
      return false;
    }
    if (_timeoutId) {
      var remainingTime = _wait - (Date.now() - _startAt);
      if (wait && remainingTime < wait) {
        return true;
      }
      clear();
    }
    return false;
  }

  /**
   * Prepare request to be sent away
   *
   * @param {number=} wait
   * @param {boolean=false} retrying
   * @returns {Promise}
   * @private
   */
  function _prepareRequest(_ref3 /*:: */) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
    var wait = _ref3 /*:: */.wait,
      retrying = _ref3 /*:: */.retrying;
    // if (!_baseUrlsIterator) {
    //   _baseUrlsIterator = getBaseUrlsIterator()
    //   _baseUrlsIteratorCurrent = _baseUrlsIterator.next()
    // }

    _wait = wait ? _prepareWait(wait) : _wait;
    if (_skip(wait)) {
      return request_Promise.resolve({
        status: 'error',
        action: 'CONTINUE',
        response: '',
        message: HTTP_ERRORS.SKIP,
        code: 'SKIP'
      });
    }
    console.log('att get _url ', _url);
    if (!_url) {
      sdk_logger.error('You must define url for the request to be sent');
      return request_Promise.reject({
        status: 'error',
        action: 'CONTINUE',
        response: '',
        message: HTTP_ERRORS.MISSING_URL,
        code: 'MISSING_URL'
      });
    }
    sdk_logger.log("".concat(retrying ? 'Re-trying' : 'Trying', " request ").concat(_url, " in ").concat(_wait, "ms"));
    _startAt = Date.now();

    //_getBaseUrl(_baseUrlsIteratorCurrent.value, _url)
    return _preRequest({
      endpoint: constants_configs.base_url,
      url: _url,
      method: _method,
      params: _objectSpread2({
        attempts: 1
      }, _params)
    });
  }

  /**
   * Check if there is internet connect and if not then setup the timeout
   *
   * @param {Object} options
   * @returns {Promise}
   * @private
   */
  function _preRequest(options /*: HttpRequestParamsT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
    _clearTimeout();
    if (isConnected()) {
      return _request(options);
    }
    _attempts.connection += 1;
    sdk_logger.log("No internet connectivity, trying request ".concat(options.url, " in ").concat(NO_CONNECTION_WAIT, "ms"));
    return new request_Promise(function (resolve) {
      _timeoutId = setTimeout(function () {
        resolve(_preRequest(options));
      }, NO_CONNECTION_WAIT);
    });
  }

  /**
   * Do the timed-out request with retry mechanism
   *
   * @param {Object} options
   * @returns {Promise}
   * @private
   */
  function _request(options /*: HttpRequestParamsT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
    return new request_Promise(function (resolve, reject) {
      _timeoutId = setTimeout(function () {
        _startAt = null;
        var filteredParams = entries(options.params).filter(function (_ref4) {
          var _ref5 = _slicedToArray(_ref4, 2),
            value = _ref5[1];
          return isEmptyEntry(value);
        }).reduce(reducer, {});
        return http({
          endpoint: options.endpoint,
          url: options.url,
          method: options.method,
          params: _objectSpread2(_objectSpread2({}, filteredParams), {}, {
            attempts: (_attempts.request ? _attempts.request + 1 : 1) + _attempts.connection
          })
        }).then(function (result) {
          return _continue(result, resolve);
        }).catch(function (result) {
          return _error(result, resolve, reject);
        });
      }, _wait);
    });
  }

  /**
   * Restore to global parameters
   *
   * @private
   */
  function _restore() /*: void*/{
    _url = _default.url;
    _method = _default.method;
    _params = _objectSpread2({}, _default.params);
    _continueCb = _default.continueCb;
  }

  /**
   * Finish the request by restoring and clearing
   *
   * @param {boolean=false} failed
   * @private
   */
  function _finish(failed /*: boolean*/) /*: void*/{
    sdk_logger.log("Request ".concat(_url || 'unknown', " ").concat(failed ? 'failed' : 'has been finished'));
    _attempts.request = DEFAULT_ATTEMPTS;
    _attempts.connection = DEFAULT_ATTEMPTS;
    _wait = DEFAULT_WAIT;
    _restore();
    clear();
  }

  /**
   * Retry request with optional new waiting period
   *
   * @param {number=} wait
   * @returns {Promise}
   * @private
   */
  function _retry(wait /*: WaitT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
    _attempts.request += 1;
    clear();
    return _prepareRequest({
      wait: wait || backOff(_attempts.request, _strategy),
      retrying: true
    });
  }

  /**
   * Decide how to continue, either:
   * - retry if requested
   * - call custom success callback
   * - or finish the request by default
   *
   * @param {Object} result
   * @param {number} result.retry_in
   * @param {Function} resolve
   * @private
   */
  function _continue(result /*: HttpSuccessResponseT | HttpErrorResponseT*/, resolve) /*: void*/{
    if (result && result.retry_in) {
      resolve(_retry(result.retry_in));
      return;
    }

    //_resetBaseUrlsIterator()

    if (typeof _continueCb === 'function') {
      _continueCb(result, _finish, _retry);
    } else {
      _finish();
    }
    resolve(result);
  }

  /**
   * Ensure to resolve on retry and finish request when unknown error
   *
   * @param {Object} result
   * @param {Function} resolve
   * @param {Function} reject
   * @private
   */
  function _error(result /*: HttpErrorResponseT*/, resolve, reject) /*: void*/{
    if (result && result.action === 'RETRY') {
      if (result.code === 'NO_CONNECTION') {
        var nextEndpoint = _baseUrlsIterator.next(); // get next endpoint

        if (!nextEndpoint.done) {
          // next endpoint exists
          //_baseUrlsIteratorCurrent = nextEndpoint // use the endpoint in the next try
          resolve(_retry(DEFAULT_WAIT));
        } else {
          // no more endpoints, seems there is no connection at all
          //_resetBaseUrlsIterator()
          resolve(_retry(NO_CONNECTION_WAIT));
        }
      } else {
        resolve(_retry());
      }
      return;
    }
    _finish(true);
    reject(result || {});
  }

  /**
   * Send the request after specified or default waiting period
   *
   * @param {string=} url
   * @param {string=} method
   * @param {Object=} params
   * @param {Function=} continueCb
   * @param {number=} wait
   * @returns {Promise}
   */
  function send() /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
    var _ref6 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
      url = _ref6.url,
      method = _ref6.method,
      _ref6$params = _ref6.params,
      params = _ref6$params === void 0 ? {} : _ref6$params,
      continueCb = _ref6.continueCb,
      wait = _ref6.wait;
    _prepareParams({
      url: url,
      method: method,
      params: params,
      continueCb: continueCb
    });
    return _prepareRequest({
      wait: wait
    });
  }

  /**
   * Check if request is running
   *
   * @returns {boolean}
   */
  function isRunning() /*: boolean*/{
    return !!_timeoutId;
  }

  /**
   * Clear request/connection timeout
   *
   * @private
   */
  function _clearTimeout() /*: void*/{
    if (_timeoutId) {
      clearTimeout(_timeoutId);
    }
    _timeoutId = null;
  }

  /**
   * Clear the current request
   */
  function clear() /*: void*/{
    var stillRunning = !!_startAt;
    _clearTimeout();
    _startAt = null;
    if (stillRunning) {
      _wait = DEFAULT_WAIT;
      _attempts.request = DEFAULT_ATTEMPTS;
      _attempts.connection = DEFAULT_ATTEMPTS;
      sdk_logger.log("Previous ".concat(_url || 'unknown', " request attempt canceled"));
      _restore();
    }
  }
  return {
    send: send,
    isRunning: isRunning,
    clear: clear
  };
};
/* harmony default export */ const request = (request_Request);
;// CONCATENATED MODULE: ./src/sdk/disable.js




/*:: type StatusT = 'on' | 'off' | 'paused'*/
/*:: type ReasonT = REASON_GDPR | REASON_GENERAL*/
/*:: type PendingT = boolean*/
/*:: type ReasonMapT = {|
  reason: ReasonT,
  pending: PendingT
|}*/
/**
 * Get the disable action name depending on the reason
 *
 * @param {string} reason
 * @returns {string}
 * @private
 */
var _disableReason = function _disableReason(reason /*: ReasonT*/) {
  return reason === REASON_GDPR ? 'GDPR disable' : 'disable';
};

/**
 * Get log messages depending on the disable reason
 *
 * @param {string} reason
 * @returns {Object}
 * @private
 */
var _logMessages = function _logMessages(reason /*: ReasonT*/) {
  return {
    start: {
      inProgress: "WiseTrack SDK ".concat(_disableReason(reason), " process has already started"),
      done: "WiseTrack SDK ".concat(_disableReason(reason), " process is now started")
    },
    finish: {
      inProgress: "WiseTrack SDK ".concat(_disableReason(reason), " process has already finished"),
      done: "WiseTrack SDK ".concat(_disableReason(reason), " process is now finished")
    }
  };
};

/**
 * Start or finish disable process
 *
 * @param {string} reason
 * @param {boolean} pending
 * @param {string} expectedAction
 * @returns {boolean}
 * @private
 */
function _disable(_ref /*:: */, expectedAction /*: 'start' | 'finish'*/) /*: boolean*/{
  var reason = _ref /*:: */.reason,
    pending = _ref /*:: */.pending;
  var disabled = getDisabled() || {};
  var action = expectedAction === 'start' && disabled.pending ? 'start' : 'finish';
  var shouldNotStart = expectedAction === 'start' && disabled.reason;
  var shouldNotFinish = expectedAction === 'finish' && disabled.reason && !disabled.pending;
  if (shouldNotStart || shouldNotFinish) {
    sdk_logger.log(_logMessages(disabled.reason)[action].inProgress);
    return false;
  }
  sdk_logger.log(_logMessages(reason)[action].done);
  setDisabled({
    reason: reason || REASON_GENERAL,
    pending: pending
  });
  return true;
}

/**
 * Disable sdk due to a particular reason
 *
 * @param {string} reason
 * @param {boolean} pending
 * @private
 */
function disable(reason /*: ?ReasonT*/) /*: boolean*/{
  var pending /*: ?PendingT*/ = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
  return _disable({
    reason: reason,
    pending: pending || false
  }, 'start');
}

/**
 * Finish disable process if previously set to pending state
 *
 * @param {string} reason
 * @returns {boolean}
 */
function finish(reason /*: ReasonT*/) /*: boolean*/{
  return _disable({
    reason: reason,
    pending: false
  }, 'finish');
}

/**
 * Enable sdk if not GDPR forgotten
 */
function restore() /*: boolean*/{
  var disabled = getDisabled() || {};
  if (disabled.reason === REASON_GDPR) {
    sdk_logger.log('WiseTrack SDK is disabled due to GDPR-Forget-Me request and it can not be re-enabled');
    return false;
  }
  if (!disabled.reason) {
    sdk_logger.log('WiseTrack SDK is already enabled');
    return false;
  }
  sdk_logger.log('WiseTrack SDK has been enabled');
  setDisabled(null);
  return true;
}

/**
 * Get the current status of the sdk
 * - on: not disabled
 * - paused: partially disabled, waiting for the opt-out confirmation from the backend
 * - off: completely disabled
 *
 * @returns {string}
 */
function disable_status() /*: StatusT*/{
  var disabled = getDisabled() || {};
  if (disabled.reason === REASON_GENERAL || disabled.reason === REASON_GDPR && !disabled.pending) {
    return 'off';
  } else if (disabled.reason === REASON_GDPR && disabled.pending) {
    return 'paused';
  }
  return 'on';
}

;// CONCATENATED MODULE: ./src/sdk/identity.js

var identity_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type ActivityStateMapT } from './types';*/







/*:: type InterceptT = {|
  exists: boolean,
  stored?: ?ActivityStateMapT
|}*/
/**
 * Name of the store used by activityState
 *
 * @type {string}
 * @private
 */
var identity_storeName = 'activityState';

/**
 * Boolean used in start in order to avoid duplicated activity state
 *
 * @type {boolean}
 * @private
 */
var _starting /*: boolean*/ = false;

/**
 * Generate random  uuid v4
 *
 * @returns {string}
 * @private
 */
function _generateUuid() /*: string*/{
  var seed = Date.now();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = (seed + Math.random() * 16) % 16 | 0;
    seed = Math.floor(seed / 16);
    return (c === 'x' ? r : r & (0x3 | 0x8)).toString(16);
  });
}

/**
 * Inspect stored activity state and check if disable needs to be repeated
 *
 * @param {Object=} stored
 * @returns {Object}
 * @private
 */
function _intercept(stored /*: ActivityStateMapT*/) /*: InterceptT*/{
  if (!stored) {
    return {
      exists: false
    };
  }
  if (stored.uuid === 'unknown') {
    disable({
      reason: REASON_GDPR
    });
    activity_state.destroy();
    return {
      exists: true,
      stored: null
    };
  }
  activity_state.init(stored);
  return {
    exists: true,
    stored: stored
  };
}

/**
 * Cache stored activity state into running memory
 *
 * @returns {Promise}
 */
function start() /*: Promise<ActivityStateMapT>*/{
  if (_starting) {
    return identity_Promise.reject({
      interrupted: true,
      message: 'WiseTrack SDK start already in progress'
    });
  }
  _starting = true;
  return storage.getFirst(identity_storeName).then(_intercept).then(function (result /*: InterceptT*/) {
    if (result.exists) {
      _starting = false;
      return result.stored;
    }
    var activityState = isEmpty(activity_state.current) ? {
      uuid: _generateUuid()
    } : activity_state.current;
    return storage.addItem(identity_storeName, activityState).then(function () {
      activity_state.init(activityState);
      reload();
      _starting = false;
      return activityState;
    });
  });
}

/**
 * Check if sdk is running at all (totally disabled or inactive activity state)
 *
 * @returns {boolean}
 * @private
 */
function _isLive() {
  return disable_status() !== 'off' && activity_state.isStarted();
}

/**
 * Persist changes made directly in activity state and update lastActive flag
 *
 * @returns {Promise}
 */
function persist() /*: Promise<?ActivityStateMapT>*/{
  if (!_isLive()) {
    return identity_Promise.resolve(null);
  }
  var activityState = _objectSpread2(_objectSpread2({}, activity_state.current), {}, {
    lastActive: Date.now()
  });
  return storage.updateItem(identity_storeName, activityState).then(function () {
    return activity_state.current = activityState;
  });
}

/**
 * Sync in-memory activityState with the one from store
 * - should be used when change from another tab is possible and critical
 *
 * @returns {Promise}
 */
function sync() /*: Promise<ActivityStateMapT>*/{
  return storage.getFirst(identity_storeName).then(function (activityState /*: ActivityStateMapT*/) {
    var current = activity_state.current;
    var lastActive = current.lastActive || 0;
    if (_isLive() && lastActive < activityState.lastActive) {
      // Checking if another SDK instance was installed while this one was in backgound
      var installedUpdated = !current.installed && activityState.installed;
      var sessionCountUpdated = (current.sessionCount || 0) < (activityState.sessionCount || 0);
      if (installedUpdated || sessionCountUpdated) {
        publish('sdk:installed');
      }
      activity_state.current = activityState;
      reload();
    }
    return activityState;
  });
}

/**
 * Clear activity state store - set uuid to be unknown
 */
function clear() /*: void*/{
  var newActivityState = {
    uuid: 'unknown'
  };
  activity_state.current = newActivityState;
  return storage.clear(identity_storeName).then(function () {
    return storage.addItem(identity_storeName, newActivityState);
  });
}

/**
 * Destroy current activity state
 */
function identity_destroy() /*: void*/{
  activity_state.destroy();
}

;// CONCATENATED MODULE: ./src/sdk/queue.js


var queue_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type HttpSuccessResponseT, type HttpErrorResponseT, type HttpFinishCbT, type WaitT, type UrlT, type MethodT, type RequestParamsT, type ActivityStateMapT } from './types';*/








/*:: type PendingT = {|
  timestamp: number,
  url: UrlT,
  method?: MethodT,
  createdAt?: number,
  params: RequestParamsT
|}*/
/**
 * Http request instance
 *
 * @type {Object}
 * @private
 */
var _request = request({
  strategy: 'long',
  continueCb: _continue
});

/**
 * Check if in offline mode
 *
 * @type {boolean}
 * @private
 */
var _isOffline = false;

/**
 * Name of the store used by queue
 *
 * @type {string}
 * @private
 */
var queue_storeName = 'queue';

/**
 * Current running state and task timestamp
 *
 * @type {{running: boolean, timestamp: void|number, pause: void|Object}}
 * @private
 */
var _current
/*: {|
  running: boolean,
  timestamp: ?number,
  pause: ?{|
    timestamp: number,
    wait: WaitT
  |}
|}*/
= {
  running: false,
  timestamp: null,
  pause: null
};

/**
 * Remove from the top and continue running pending requests
 *
 * @param {Object} result
 * @param {Function} finish
 * @returns {Promise}
 * @private
 */
function _continue(result /*: HttpSuccessResponseT | HttpErrorResponseT*/, finish /*: HttpFinishCbT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT>*/{
  var wait = result && result.continue_in || null;
  _current.pause = wait ? {
    timestamp: Date.now(),
    wait: wait
  } : null;
  return storage.getFirst(queue_storeName).then(function (pending) {
    return pending ? storage.deleteItem(queue_storeName, pending.timestamp) : null;
  }).then(function () {
    finish();
    _current.running = false;
    return run({
      wait: wait
    });
  });
}

/**
 * Correct timestamp if equal or less then previous one to avoid constraint errors
 * Cases when needed:
 * - test environment
 * - when pushing to queue synchronously, one after an other
 *
 * @returns {number}
 * @private
 */
function _prepareTimestamp() /*: number*/{
  var timestamp = Date.now();
  if (_current.timestamp && timestamp <= _current.timestamp) {
    timestamp = _current.timestamp + 1;
  }
  _current.timestamp = timestamp;
  return timestamp;
}

/**
 * Persist activity state change with session offset reset after session request
 *
 * @param {string} url
 * @returns {Promise}
 * @private
 */
function _persist(url) /*: Promise<?ActivityStateMapT>*/{
  if (isRequestSession(url, 'session')) {
    activity_state.resetSessionOffset();
  }
  activity_state.updateLastActive();
  return persist();
}

/**
 * Push request to the queue
 *
 * @param {string} url
 * @param {string} method
 * @param {Object=} params
 * @param {boolean=} auto
 * @param {number=} timestamp
 * @returns {Promise}
 */
function push(_ref /*:: */) {
  var url = _ref /*:: */.url,
    method = _ref /*:: */.method,
    params = _ref /*:: */.params;
  var _ref2 = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {},
    auto = _ref2.auto,
    timestamp = _ref2.timestamp;
  activity_state.updateParams(url, auto);
  var filteredParams = entries(params || {}).filter(function (_ref3) {
    var _ref4 = _slicedToArray(_ref3, 2),
      value = _ref4[1];
    return isEmptyEntry(value);
  }).reduce(reducer, {});
  var pending /*: PendingT*/ = {
    timestamp: _prepareTimestamp(),
    url: url,
    method: method,
    params: _objectSpread2(_objectSpread2({}, activity_state.getParams(url)), filteredParams)
  };
  if (timestamp) {
    pending.createdAt = timestamp;
  }
  return storage.addItem(queue_storeName, pending).then(function () {
    return _persist(url);
  }).then(function () {
    return _current.running ? {} : run();
  });
}

/**
 * Prepare to send pending request if available
 *
 * @param {number} timestamp
 * @param {number=} createdAt
 * @param {string=} url
 * @param {string=} method
 * @param {Object=} params
 * @param {number=} wait
 * @returns {Promise}
 * @private
 */
function _prepareToSend() /*: Promise<mixed>*/{
  var _ref5 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
    timestamp = _ref5.timestamp,
    createdAt = _ref5.createdAt,
    url = _ref5.url,
    method = _ref5.method,
    params = _ref5.params;
  var wait /*:: ?: ?WaitT*/ = arguments.length > 1 ? arguments[1] : undefined;
  var activityState = activity_state.current || {};
  var firstSession = url === '/session' && !activityState.installed;
  var noPending = !url && !method && !params;
  if (_isOffline && !firstSession || noPending) {
    _current.running = false;
    return queue_Promise.resolve({});
  }
  return _request.send({
    url: url,
    method: method,
    params: _objectSpread2(_objectSpread2({}, params), {}, {
      createdAt: getTimestamp(createdAt || timestamp)
    }),
    wait: wait || _checkWait()
  });
}

/**
 * Check if there is waiting period required
 *
 * @returns {void|number}
 * @private
 */
function _checkWait() /*: ?WaitT*/{
  var _ref6 = _current.pause || {},
    timestamp = _ref6.timestamp,
    wait = _ref6.wait;
  var rest = Date.now() - (timestamp || 0);
  return rest < wait ? wait - rest : null;
}

/**
 * Run all pending requests
 *
 * @param {boolean=false} cleanUp
 * @param {number=} wait
 * @returns {Promise}
 */
function run() /*: Promise<mixed>*/{
  var _ref7 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
    cleanUp = _ref7.cleanUp,
    wait = _ref7.wait;
  if (_current.running) {
    return queue_Promise.resolve({});
  }
  _current.running = true;
  var chain = queue_Promise.resolve({});
  if (cleanUp) {
    chain = chain.then(_cleanUp);
  }
  return chain.then(function () {
    return storage.getFirst(queue_storeName);
  }).then(function (pending) {
    return _prepareToSend(pending, wait);
  });
}

/**
 * Set offline mode to on or off
 * - if on then all requests are queued
 * - if off then run all pending requests
 *
 * @param {boolean} state
 */
function setOffline(state /*: boolean*/) /*: void*/{
  if (state === undefined) {
    sdk_logger.error('State not provided, true or false has to be defined');
    return;
  }
  if (state === _isOffline) {
    sdk_logger.error("The app is already in ".concat(state ? 'offline' : 'online', " mode"));
    return;
  }
  var wasOffline = _isOffline;
  _isOffline = state;
  if (!state && wasOffline) {
    run();
  }
  sdk_logger.info("The app is now in ".concat(state ? 'offline' : 'online', " mode"));
}

/**
 * Clean up stale pending requests
 *
 * @private
 * @returns {Promise}
 */
function _cleanUp() /*: Promise<mixed>*/{
  var upperBound = Date.now() - config.requestValidityWindow;
  return storage.deleteBulk(queue_storeName, upperBound, 'upperBound');
}

/**
 * Check if there is pending timeout to be flushed
 * i.e. if queue is running
 *
 * @returns {boolean}
 */
function isRunning() /*: boolean*/{
  return _current.running;
}

/**
 * Clear queue store
 */
function queue_clear() /*: void*/{
  return storage.clear(queue_storeName);
}

/**
 * Destroy queue by clearing current timeout
 */
function queue_destroy() /*: void*/{
  _request.clear();
  _current.running = false;
  _current.timestamp = null;
  _current.pause = null;
}

;// CONCATENATED MODULE: ./src/sdk/global-params.js

var global_params_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type GlobalParamsT, type GlobalParamsMapT } from './types';*/



/*:: type TypeT = 'callback' | 'partner'*/
/*:: type KeysT = [string, TypeT]*/
/*:: type KeysArrayT = Array<KeysT>*/
/**
 * Name of the store used by global params
 *
 * @type {string}
 * @private
 */
var global_params_storeName = 'globalParams';

/**
 * Error message for type missing
 *
 * @type {Object}
 * @private
 */
var _error = {
  short: 'No type provided',
  long: 'Global parameter type not provided, `callback` or `partner` types are available'
};

/**
 * Omit type parameter from the collection
 *
 * @param {Array} params
 * @returns {Array}
 * @private
 */
function _omitType(params) /*: Array<GlobalParamsT>*/{
  return (params || []).map(function (_ref) {
    var key = _ref.key,
      value = _ref.value;
    return {
      key: key,
      value: value
    };
  });
}

/**
 * Get callback and partner global parameters
 *
 * @returns {Promise}
 */
function get() /*: Promise<GlobalParamsMapT>*/{
  return global_params_Promise.all([storage.filterBy(global_params_storeName, 'callback'), storage.filterBy(global_params_storeName, 'partner')]).then(function (_ref2) {
    var _ref3 = _slicedToArray(_ref2, 2),
      callbackParams = _ref3[0],
      partnerParams = _ref3[1];
    return {
      callbackParams: _omitType(callbackParams),
      partnerParams: _omitType(partnerParams)
    };
  });
}

/**
 * Add global parameters, either callback or partner params
 *
 * @param {Array} params
 * @param {string} type
 * @returns {Promise}
 */
function add(params /*: Array<GlobalParamsT>*/, type /*: TypeT*/) /*: void | Promise<KeysArrayT>*/{
  if (type === undefined) {
    sdk_logger.error(_error.long);
    return global_params_Promise.reject({
      message: _error.short
    });
  }
  /*:: type GlobalParamsWithTypeT = {|...GlobalParamsT, type: string|}*/
  var map /*: {[key: string]: string}*/ = convertToMap(params);
  var prepared /*: Array<GlobalParamsWithTypeT>*/ = Object.keys(map).map(function (key) {
    return {
      key: key,
      value: map[key],
      type: type
    };
  });
  return global_params_Promise.all([storage.filterBy(global_params_storeName, type), storage.addBulk(global_params_storeName, prepared, true)]).then(function (_ref4) {
    var _ref5 = _slicedToArray(_ref4, 2),
      oldParams = _ref5[0],
      newParams = _ref5[1];
    var intersecting = intersection(oldParams.map(function (param) {
      return param.key;
    }), newParams.map(function (param) {
      return param[0];
    }));
    sdk_logger.log("Following ".concat(type, " parameters have been saved: ").concat(prepared.map(function (p) {
      return "".concat(p.key, ":").concat(p.value);
    }).join(', ')));
    if (intersecting.length) {
      sdk_logger.log("Keys: ".concat(intersecting.join(', '), " already existed so their values have been updated"));
    }
    return newParams;
  });
}

/**
 * Remove global parameter by key and type
 *
 * @param {string} key
 * @param {string} type
 * @returns {Promise}
 */
function remove(key /*: string*/, type /*: TypeT*/) /*: void | Promise<KeysT>*/{
  if (type === undefined) {
    sdk_logger.error(_error.long);
    return global_params_Promise.reject({
      message: _error.short
    });
  }
  return storage.deleteItem(global_params_storeName, [key, type]).then(function (result) {
    sdk_logger.log("".concat(key, " ").concat(type, " parameter has been deleted"));
    return result;
  });
}

/**
 * Remove all global parameters of certain type
 * @param {string} type
 * @returns {Promise}
 */
function removeAll(type /*: TypeT*/) /*: void | Promise<KeysArrayT>*/{
  if (type === undefined) {
    sdk_logger.error(_error.long);
    return global_params_Promise.reject({
      message: _error.short
    });
  }
  return storage.deleteBulk(global_params_storeName, type).then(function (result) {
    sdk_logger.log("All ".concat(type, " parameters have been deleted"));
    return result;
  });
}

/**
 * Clear globalParams store
 */
function global_params_clear() /*: void*/{
  return storage.clear(global_params_storeName);
}

;// CONCATENATED MODULE: ./src/sdk/attribution.js


var attribution_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type HttpSuccessResponseT, type HttpErrorResponseT, type HttpFinishCbT, type HttpRetryCbT, type AttributionStateT, type AttributionWhiteListT, type AttributionMapT } from './types';*/










/**
 * Http request instance
 *
 * @type {Object}
 * @private
 */
var attribution_request = request({
  url: '/attribution',
  strategy: 'short',
  continueCb: attribution_continue
});

/**
 * List of valid attribution parameters
 *
 * @type {string[]}
 * @private
 */
var _whitelist /*: AttributionWhiteListT*/ = ['tracker_token', 'tracker_name', 'network', 'campaign', 'adgroup', 'creative', 'click_label', 'state'];

/**
 * Check if new attribution is the same as old one
 *
 * @param {string} adid
 * @param {Object=} attribution
 * @returns {boolean}
 * @private
 */
function _isSame(_ref /*:: */) /*: boolean*/{
  var adid = _ref /*:: */.adid,
    attribution = _ref /*:: */.attribution;
  var oldAttribution = activity_state.current.attribution || {};
  var anyDifferent = attribution && _whitelist.some(function (k) {
    return oldAttribution[k] !== attribution[k];
  });
  return !anyDifferent && adid === oldAttribution.adid;
}

/**
 * Check if attribution result is valid
 *
 * @param {string} adid
 * @param {Object=} attribution
 * @returns {boolean}
 * @private
 */
function _isValid(_ref2 /*:: */) /*: boolean*/{
  var _ref2$adid = _ref2 /*:: */.adid,
    adid = _ref2$adid === void 0 ? '' : _ref2$adid,
    _ref2$attribution = _ref2 /*:: */.attribution,
    attribution = _ref2$attribution === void 0 ? {} : _ref2$attribution;
  return !!adid && !!intersection(_whitelist, Object.keys(attribution)).length;
}

/**
 * Update attribution and initiate client's callback
 *
 * @param {Object} result
 * @private
 */
function _setAttribution(result /*: HttpSuccessResponseT*/) /*: Promise<AttributionStateT>*/{
  if (isEmpty(result) || !_isValid(result) || _isSame(result)) {
    return attribution_Promise.resolve({
      state: 'same'
    });
  }
  var attribution /*: AttributionMapT*/ = entries(result.attribution).filter(function (_ref3) {
    var _ref4 = _slicedToArray(_ref3, 1),
      key = _ref4[0];
    return _whitelist.indexOf(key) !== -1;
  }).reduce(reducer, {
    adid: result.adid
  });
  activity_state.current = _objectSpread2(_objectSpread2({}, activity_state.current), {}, {
    attribution: attribution
  });
  return persist().then(function () {
    publish('attribution:change', attribution);
    sdk_logger.info('Attribution has been updated');
    return {
      state: 'changed'
    };
  });
}

/**
 * Store attribution or make another request if attribution not yet available
 *
 * @param {Object} result
 * @param {Function} finish
 * @param {Function} retry
 * @returns {Promise}
 * @private
 */
function attribution_continue(result /*: HttpSuccessResponseT | HttpErrorResponseT*/, finish /*: HttpFinishCbT*/, retry /*: HttpRetryCbT*/) /*: Promise<HttpSuccessResponseT | HttpErrorResponseT | AttributionStateT>*/{
  if (!result || result && result.status === 'error') {
    finish();
    return attribution_Promise.resolve({
      state: 'unknown'
    });
  }
  if (!result.ask_in) {
    finish();
    return _setAttribution(result);
  }
  return retry(result.ask_in);
}

/**
 * Request attribution if session asked for it
 *
 * @param {Object=} sessionResult
 * @param {number=} sessionResult.ask_in
 */
function check(sessionResult /*: HttpSuccessResponseT*/) /*: Promise<mixed>*/{
  var activityState = activity_state.current;
  var askIn = (sessionResult || {}).ask_in;
  console.log('check attribution 0000');
  if (!askIn && (activityState.attribution || !activityState.installed)) {
    return attribution_Promise.resolve(activityState);
  }
  console.log('check attribution');

  // _request.send({
  //   params: {
  //     initiatedBy: !sessionResult ? 'sdk' : 'backend',
  //     ...ActivityState.getParams()
  //   },
  //   wait: askIn
  // })

  activity_state.updateSessionOffset();
  console.log('att', constants_configs.attributions);
  return get().then(function (globalParams) {
    console.log('configls', globalParams);
    push({
      url: constants_configs.attributions,
      method: 'POST',
      params: activity_state.getParams()
    }, {
      auto: true
    });
  });

  // return persist()
}

/**
 * Destroy attribution by clearing running request
 */
function attribution_destroy() /*: void*/{
  attribution_request.clear();
}

;// CONCATENATED MODULE: ./src/sdk/session.js
var session_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type DocumentT, type HttpSuccessResponseT, type HttpErrorResponseT, type GlobalParamsMapT, type SessionRequestParamsT } from './types';*/















/**
 * Flag to mark if session watch is already on
 *
 * @type {boolean}
 * @private
 */
var _running = false;

/**
 * Reference to interval id to be used for clearing
 *
 * @type {number}
 * @private
 */
var _idInterval /*: ?IntervalID*/;

/**
 * Reference to timeout id to be used for clearing
 *
 * @type {number}
 * @private
 */
var _idTimeout /*: ?TimeoutID*/;

/**
 * Browser-specific prefixes for accessing Page Visibility API
 *
 * @type {{hidden, visibilityChange}}
 * @private
 */
var _pva;

/**
 * Reference to the document casted to a plain object
 *
 * @type {Document}
 */
var documentExt = (document /*: DocumentT*/);

/**
 * Initiate session watch:
 * - bind to visibility change event to track window state (if out of focus or closed)
 * - initiate activity state params and visibility state
 * - check session initially
 * - set the timer to update last active timestamp
 *
 * @returns {Promise}
 */
function watch() /*: Promise<mixed>*/{
  _pva = getVisibilityApiAccess();
  if (_running) {
    return session_Promise.reject({
      interrupted: true,
      message: 'Session watch already initiated'
    });
  }
  _running = true;
  subscribe('session:finished', _handleSessionRequestFinish);
  if (_pva) {
    on(documentExt, _pva.visibilityChange, _handleVisibilityChange);
  }
  if (_pva && documentExt[_pva.hidden]) {
    sdk_logger.log('Session request attempt canceled because the tab is still hidden');
    return session_Promise.resolve({});
  }
  activity_state.initParams();
  return _checkSession();
}

/**
 * Check if session watch is running
 *
 * @returns {boolean}
 */
function session_isRunning() /*: boolean*/{
  return _running;
}

/**
 * Destroy session watch
 */
function session_destroy() /*: void*/{
  _running = false;
  activity_state.toBackground();
  _stopTimer();
  if (_pva) {
    clearTimeout(_idTimeout);
    off(documentExt, _pva.visibilityChange, _handleVisibilityChange);
    on(documentExt, _pva.visibilityChange, _restoreAfterAsyncEnable);
  }
}

/**
 * Handle transit to background:
 * - stop the timer
 * - update session params
 * - persist changes (store updated activity state)
 *
 * @returns {Promise}
 * @private
 */
function _handleBackground() /*: Promise<mixed>*/{
  _stopTimer();
  activity_state.updateSessionOffset();
  activity_state.toBackground();
  return persist();
}

/**
 * Handle transit to foreground:
 * - update session length
 * - check for the session and restart the timer
 *
 * @returns {Promise}
 * @private
 */
function _handleForeground() /*: Promise<mixed>*/{
  return sync().then(function () {
    activity_state.updateSessionLength();
    activity_state.toForeground();
  }).then(_checkSession);
}

/**
 * Handle visibility change and perform appropriate actions
 *
 * @private
 */
function _handleVisibilityChange() /*: void*/{
  clearTimeout(_idTimeout);
  var handler = _pva && documentExt[_pva.hidden] ? _handleBackground : _handleForeground;
  _idTimeout = setTimeout(handler, 0);
}
function _restoreAfterAsyncEnable() /*: void*/{
  if (!_pva || documentExt[_pva.hidden]) {
    return;
  }
  reload();
  if (!_running && disable_status() === 'on') {
    off(documentExt, _pva.visibilityChange, _restoreAfterAsyncEnable);
    main.__internal__.restartAfterAsyncEnable();
  }
}

/**
 * Handle session request finish; update installed state
 *
 * @param {string} e
 * @param {Object} result
 * @returns {Promise|void}
 * @private
 */
function _handleSessionRequestFinish(e /*: string*/, result /*: HttpSuccessResponseT | HttpErrorResponseT*/) /*: ?Promise<mixed>*/{
  if (result && result.status === 'error') {
    sdk_logger.error('Session was not successful, error was returned from the server:', result.response);
    return;
  }
  activity_state.updateInstalled();
  publish('sdk:installed');
  return persist();
}

/**
 * Start the session timer, every N seconds:
 * - update session params
 * - persist changes (store updated activity state)
 *
 * @private
 */
function _startTimer() /*: void*/{
  _stopTimer();
  _idInterval = setInterval(function () {
    activity_state.updateSessionOffset();
    return persist();
  }, config.sessionTimerWindow);
}

/**
 * Stop the session timer
 *
 * @private
 */
function _stopTimer() /*: void*/{
  clearInterval(_idInterval);
}

/**
 * Prepare parameters for the session tracking
 * @param {string} referrer
 * @param {Array} callbackParams
 * @param {Array} partnerParams
 * @returns {Object}
 * @private
 */
function _prepareParams(_ref /*:: */) /*: SessionRequestParamsT*/{
  var callbackParams = _ref /*:: */.callbackParams,
    partnerParams = _ref /*:: */.partnerParams;
  var referrer = localStorage.getItem('referrer_key');
  return {
    referrer: referrer,
    callbackParams: callbackParams.length ? convertToMap(callbackParams) : null,
    partnerParams: partnerParams.length ? convertToMap(partnerParams) : null
  };
}

/**
 * Track session by sending the request to the server
 *
 * @private
 */
function _trackSession() /*: Promise<mixed>*/{
  return get().then(function (globalParams) {
    push({
      url: constants_configs.sessions,
      method: 'POST',
      params: _prepareParams(globalParams)
    }, {
      auto: true
    });
  });
}

/**
 * Check if session needs to be tracked
 *
 * @private
 */
function _checkSession() /*: Promise<mixed>*/{
  _startTimer();
  var activityState = activity_state.current;
  var lastInterval = activityState.lastInterval;
  var isEnqueued = activityState.sessionCount > 0;
  var currentWindow = lastInterval;
  if (!isEnqueued || isEnqueued && currentWindow >= constants_configs.session_interval) {
    return _trackSession();
  } else {
    if (activity_state.isNewlyOpened()) {
      if (!activity_state.isRefreshWebSite()) {
        return _trackSession();
      }
    }
  }
  check({
    ask_in: 1000
  });
  publish('attribution:check');
  return persist();
}

;// CONCATENATED MODULE: ./src/sdk/gdpr-forget-device.js









/**
 * Http request instance
 *
 * @type {Object}
 * @private
 */
var gdpr_forget_device_request = request({
  url: '/gdpr_forget_device',
  method: 'POST',
  strategy: 'short'
});

/**
 * Log messages used in different scenarios
 *
 * @type {Object}
 * @private
 */
var gdpr_forget_device_logMessages = {
  running: 'WiseTrack SDK is running pending GDPR Forget Me request',
  pending: 'WiseTrack SDK will run GDPR Forget Me request after initialisation',
  paused: 'WiseTrack SDK is already prepared to send GDPR Forget Me request',
  off: 'WiseTrack SDK is already disabled'
};

/**
 * Request GDPR-Forget-Me in order to disable sdk
 *
 * @param {boolean} force
 * @returns {boolean}
 */
function forget(force /*: boolean*/) /*: boolean*/{
  var sdkStatus = disable_status();
  if (!force && sdkStatus !== 'on') {
    sdk_logger.log(gdpr_forget_device_logMessages[sdkStatus]);
    return false;
  }
  if (!config.isInitialised()) {
    sdk_logger.log(gdpr_forget_device_logMessages.pending);
    return true;
  }
  gdpr_forget_device_request.send({
    params: _objectSpread2({}, activity_state.getParams())
  }).then(function () {
    publish('sdk:gdpr-forget-me');
  });
  return true;
}

/**
 * Start disable of the sdk due to GDPR-Forget-me request
 *
 * @returns {boolean}
 */
function gdpr_forget_device_disable() {
  return disable(REASON_GDPR, true);
}

/**
 * Finish disable of the sdk due to GDRP-Forget-me request
 *
 * @returns {boolean}
 */
function gdpr_forget_device_finish() {
  return finish(REASON_GDPR);
}

/**
 * Check if there is pending GDPR-Forget-Me request
 */
function gdpr_forget_device_check() /*: void*/{
  if (disable_status() === 'paused') {
    sdk_logger.log(gdpr_forget_device_logMessages.running);
    forget(true);
  }
}

/**
 * Destroy by clearing running request
 */
function gdpr_forget_device_destroy() /*: void*/{
  gdpr_forget_device_request.clear();
}

;// CONCATENATED MODULE: ./src/sdk/third-party-sharing.js






/*:: type ThirdPartySharingStatusT = 'pending' | 'on' | 'off'*/
/**
 * Log messages used in different scenarios
 *
 * @type {Object}
 * @private
 */
var third_party_sharing_logMessages = {
  running: 'WiseTrack SDK is running pending third-party sharing opt-out request',
  delayed: 'WiseTrack SDK will run third-party sharing opt-out request after initialisation',
  pending: 'WiseTrack SDK already queued third-party sharing opt-out request',
  off: 'Third-party sharing opt-out is already done',
  start: {
    inProgress: 'Third-party sharing opt-out has already started',
    done: 'Third-party sharing opt-out is now started'
  },
  finish: {
    inProgress: 'Third-party sharing opt-out has already finished',
    done: 'Third-party sharing opt-out is now finished'
  }
};

/**
 * Get the status of the third-party sharing
 *
 * @returns {string}
 * @private
 */
function _status() /*: ThirdPartySharingStatusT*/{
  var disabled = getThirdPartySharing() || {};
  if (disabled.reason) {
    return disabled.pending ? 'pending' : 'off';
  }
  return 'on';
}

/**
 * Request third-party sharing opt-out request
 *
 * @param {boolean} force
 * @returns {boolean}
 */
function optOut(force /*: boolean*/) {
  var status = _status();
  if (!force && status !== 'on') {
    sdk_logger.log(third_party_sharing_logMessages[status]);
    return false;
  }
  if (!config.isInitialised()) {
    sdk_logger.log(third_party_sharing_logMessages.delayed);
    return true;
  }
  push({
    url: '/disable_third_party_sharing',
    method: 'POST'
  });
  return true;
}

/**
 * Start or finish thrid-party sharing disable process
 *
 * @param {boolean} pending
 * @param {string} expectedAction
 * @returns {boolean}
 * @private
 */
function third_party_sharing_disable(pending /*: boolean*/, expectedAction /*: 'start' | 'finish'*/) /*: boolean*/{
  var disabled = getThirdPartySharing() || {};
  var action = expectedAction === 'start' && pending ? 'start' : 'finish';
  var shouldNotStart = expectedAction === 'start' && disabled.reason;
  var shouldNotFinish = expectedAction === 'finish' && disabled.reason && !disabled.pending;
  if (shouldNotStart || shouldNotFinish) {
    sdk_logger.log(third_party_sharing_logMessages[action].inProgress);
    return false;
  }
  sdk_logger.log(third_party_sharing_logMessages[action].done);
  setThirdPartySharing({
    reason: REASON_GENERAL,
    pending: pending
  });
  return true;
}

/**
 * Start the third-party sharing disable process
 *
 * @returns {boolean}
 */
function sdk_third_party_sharing_disable() /*: boolean*/{
  return third_party_sharing_disable(true, 'start');
}

/**
 * Finalize the third-party sharing process
 *
 * @returns {boolean}
 */
function third_party_sharing_finish() {
  return third_party_sharing_disable(false, 'finish');
}

/**
 * Check if there s pending third-party sharing opt-out request
 */
function third_party_sharing_check() /*: void*/{
  if (_status() === 'pending') {
    sdk_logger.log(third_party_sharing_logMessages.running);
    optOut(true);
  }
}

;// CONCATENATED MODULE: ./src/sdk/scheduler.js


/*:: type TaskT = {|
  method: (timestamp?: number) => mixed,
  description: string,
  timestamp: number
|}*/
/**
 * Delayed tasks list
 *
 * @type {Array}
 * @private
 */
var _tasks /*: Array<TaskT>*/ = [];

/**
 * Put the dask in the delayed list
 *
 * @param {Function} method
 * @param {string} description
 */
function delay(method /*: $PropertyType<TaskT, 'method'>*/, description /*: $PropertyType<TaskT, 'description'>*/) /*: void*/{
  _tasks.push({
    method: method,
    description: description,
    timestamp: Date.now()
  });
}

/**
 * Flush all delayed tasks
 */
function flush() /*: void*/{
  _tasks.forEach(function (task /*: TaskT*/) {
    if (typeof task.method === 'function') {
      sdk_logger.log("Delayed ".concat(task.description, " task is running now"));
      task.method(task.timestamp);
    }
  });
  _tasks = [];
}

/**
 * Destroy all pending tasks
 */
function scheduler_destroy() /*: void*/{
  _tasks = [];
}

;// CONCATENATED MODULE: ./src/sdk/event.js

var event_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type EventParamsT, type EventRequestParamsT, type GlobalParamsMapT, type GlobalKeyValueParamsT } from './types';*/







/*:: type RevenueT = {
  revenue: string,
  currency: string
}*/
var DEFAULT_EVENT_DEDUPLICATION_LIST_LIMIT = 10;

/**
 * Name of the store used by event deduplication ids
 *
 * @type {string}
 * @private
 */
var event_storeName = 'eventDeduplication';

/**
 * Get revenue value if positive and limit to 5 decimal places
 *
 * @param {number=} revenue
 * @param {string=} currency
 * @returns {Object}
 * @private
 */
function _getRevenue(revenue /*: number | void*/, currency /*: string | void*/) /*: RevenueT*/{
  if (isNaN(revenue)) {
    return {};
  }
  revenue = parseFloat(revenue);
  if (revenue < 0 || !currency) {
    return {};
  }
  return {
    revenue: revenue.toFixed(5),
    currency: currency
  };
}

/**
 * Prepare parameters for the event tracking
 *
 * @param {Object} params
 * @param {string} params.eventToken
 * @param {number=} params.revenue
 * @param {string=} params.currency
 * @param {Array=} params.callbackParams
 * @param {Array=} params.partnerParams
 * @param {Array} callbackParams
 * @param {Array} partnerParams
 * @returns {Object}
 * @private
 */
function event_prepareParams(params /*: EventParamsT*/, _ref /*:: */) /*: EventRequestParamsT*/{
  var callbackParams = _ref /*:: */.callbackParams,
    partnerParams = _ref /*:: */.partnerParams;
  var globalParams = {};
  var baseParams = _objectSpread2({
    eventToken: params.eventToken,
    deduplicationId: params.deduplicationId
  }, _getRevenue(params.revenue, params.currency));
  var eventCallbackParams /*: GlobalKeyValueParamsT*/ = _objectSpread2(_objectSpread2({}, convertToMap(callbackParams)), convertToMap(params.callbackParams));
  var eventPartnerParams /*: GlobalKeyValueParamsT*/ = _objectSpread2(_objectSpread2({}, convertToMap(partnerParams)), convertToMap(params.partnerParams));
  if (!isEmpty(eventCallbackParams)) {
    globalParams.callbackParams = eventCallbackParams;
  }
  if (!isEmpty(eventPartnerParams)) {
    globalParams.partnerParams = eventPartnerParams;
  }
  return _objectSpread2(_objectSpread2({}, baseParams), globalParams);
}

/**
 * Get event deduplication ids
 *
 * @returns {Promise}
 * @private
 */
function _getEventDeduplicationIds() /*: Promise<Array<string>>*/{
  return storage.getAll(event_storeName).then(function (records) {
    return records.map(function (record) {
      return record.id;
    });
  });
}

/**
 * Push event deduplication id and trim the store if out of the limit
 *
 * @param {string} id
 * @returns {Promise}
 * @private
 */
function _pushEventDeduplicationId(id /*: string*/) /*: Promise<number>*/{
  var customLimit = config.getCustomConfig().eventDeduplicationListLimit;
  var limit = customLimit > 0 ? customLimit : DEFAULT_EVENT_DEDUPLICATION_LIST_LIMIT;
  return storage.count(event_storeName).then(function (count) {
    var chain = event_Promise.resolve();
    if (count >= limit) {
      var removeLength = count - limit + 1;
      sdk_logger.log("Event deduplication list limit has been reached. Oldest ids are about to be removed (".concat(removeLength, " of them)"));
      chain = storage.trimItems(event_storeName, removeLength);
    }
    return chain;
  }).then(function () {
    sdk_logger.info("New event deduplication id is added to the list: ".concat(id));
    return storage.addItem(event_storeName, {
      id: id
    });
  });
}

/**
 * Check if deduplication id is already stored
 * - if yes then reject
 * - if not then push the id into storage
 *
 * @param {string=} id
 * @returns {Promise}
 * @private
 */
function _checkEventDeduplicationId(id /*: string*/) /*: Promise<?number>*/{
  if (!id) {
    return event_Promise.resolve();
  }
  return _getEventDeduplicationIds().then(function (list) {
    return list.indexOf(id) === -1 ? _pushEventDeduplicationId(id) : event_Promise.reject({
      message: "Event won't be tracked, since it was previously tracked with the same deduplication id ".concat(id)
    });
  });
}

/**
 * Track event by sending the request to the server
 *
 * @param {Object} params
 * @param {number=} timestamp
 * @return Promise
 */
function event_event(params /*: EventParamsT*/, timestamp /*: number*/) /*: Promise<void>*/{
  if (!params || params && (isEmpty(params) || !params.eventToken)) {
    var reason = 'You must provide event token in order to track event';
    sdk_logger.error(reason);
    return event_Promise.reject(reason);
  }
  console.log("event url::  ".concat(constants_configs.events));
  return _checkEventDeduplicationId(params.deduplicationId).then(get).then(function (globalParams) {
    return push({
      url: constants_configs.events,
      method: 'POST',
      params: event_prepareParams(params, globalParams)
    }, {
      timestamp: timestamp
    });
  }).catch(function (error) {
    if (error && error.message) {
      sdk_logger.error(error.message);
    }
    return event_Promise.reject(error);
  });
}
;// CONCATENATED MODULE: ./src/sdk/sdk-click.js
/*:: // 
import { type SdkClickRequestParamsT } from './types';*/




var default_utm = 'utm_source=other&utm_medium=organic';
var referrer_key = 'referrer_key';

/**
 * Check the following:
 * - redirected from somewhere other then client's website
 * - there is wisetrack_referrer query param
 *
 * @returns {boolean}
 * @private
 */
function sdk_click_getReferrer() /*: ?string*/{
  return window.location.search.substring(1).split('&').map(function (pair) {
    return pair.split('=');
  }).reduce(reducer, {})['wisetrack_referrer'];
}

/**
 * Prepare params for the sdk click request
 *
 * @param {string} referrer
 * @returns {Object}
 * @private
 */
function sdk_click_prepareParams(referrer, recently_open) /*: SdkClickRequestParamsT*/{
  return {
    installedAt: getTimestamp(),
    source: 'web_referrer',
    recentlyOpen: recently_open,
    referrer: decodeURIComponent(referrer)
  };
}

/**
 * Sends sdk_click request with manually settled referrer or with automatically grabbed one
 */
function sdkClick(manualReferrer /*: string*/, timestamp /*: number*/) /*: void*/{
  var referrer;
  var recently_open = '0';
  if (manualReferrer) {
    referrer = manualReferrer;
  } else {
    referrer = sdk_click_getReferrer();
    if (referrer == null || referrer == undefined || referrer == 'undefined') {
      referrer = default_utm;
    }
  }
  if (referrer !== default_utm) {
    referrer = default_utm + '&' + referrer;
  }
  if (localStorage.getItem(referrer_key) == null) {
    recently_open = '0';
  } else {
    recently_open = '1';
  }
  localStorage.setItem(referrer_key, decodeURIComponent(referrer));
  if (referrer) {
    push({
      url: constants_configs.sdk_clicks,
      method: 'POST',
      params: sdk_click_prepareParams(referrer, recently_open)
    }, {
      timestamp: timestamp
    });
  }
}
;// CONCATENATED MODULE: ./src/sdk/smart-banner/detect-os.ts
/**
 * Operation systems
 */
var DeviceOS;

/**
 * Returns one of android, ios, windows, windows-phone or undefined for another OS.
 */
(function (DeviceOS) {
  DeviceOS["Android"] = "android";
  DeviceOS["iOS"] = "ios";
  DeviceOS["WindowsPC"] = "windows";
  DeviceOS["WindowsPhone"] = "windows-phone";
})(DeviceOS || (DeviceOS = {}));
function getDeviceOS() /*: Maybe<DeviceOS>*/{
  var _navigator, _navigator$userAgent;
  var userAgent = (_navigator = navigator) === null || _navigator === void 0 ? void 0 : (_navigator$userAgent = _navigator.userAgent) === null || _navigator$userAgent === void 0 ? void 0 : _navigator$userAgent.toLowerCase();
  if (!userAgent || userAgent.length < 1) {
    return undefined;
  }
  if (/ipad|iphone|ipod/.test(userAgent)) {
    return DeviceOS.iOS;
  }

  // Checking Windows first because Lumia devices could have for example
  // "Mozilla/5.0 (Windows Mobile 10; Android 8.0.0; Microsoft; Lumia 950XL) ..." user agent
  if (userAgent.includes('windows')) {
    if (/phone|mobile/.test(userAgent)) {
      return DeviceOS.WindowsPhone;
    }
    return DeviceOS.WindowsPC;
  }
  if (userAgent.includes('android')) {
    return DeviceOS.Android;
  }
  return undefined;
}
;// CONCATENATED MODULE: ./src/sdk/smart-banner/utilities.ts
/**
 * Wraps JSON.parse() with try-catch.
 * Returns parsed object if successfully parsed and null otherwise.
 */
function parseJson(str /*: string | null*/) /*: any*/{
  if (!str) {
    return null;
  }
  try {
    return JSON.parse(str);
  } catch (error) {
    return null;
  }
}
;// CONCATENATED MODULE: ./src/sdk/smart-banner/storage/local-storage.ts



var LocalStorage = /*#__PURE__*/function () {
  function LocalStorage() {
    var storageName /*: string*/ = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'wisetrack-smart-banner';
    _classCallCheck(this, LocalStorage);
    this.storageName /*:: */ = storageName /*:: */;
  }
  _createClass(LocalStorage, [{
    key: "setItem",
    value: function setItem(key /*: string*/, value /*: any*/) /*: void*/{
      localStorage.setItem("".concat(this.storageName, ".").concat(key), JSON.stringify(value));
    }
  }, {
    key: "getItem",
    value: function getItem(key /*: string*/) /*: any | null*/{
      var value = localStorage.getItem("".concat(this.storageName, ".").concat(key));
      return parseJson(value);
    }
  }, {
    key: "removeItem",
    value: function removeItem(key /*: string*/) /*: void*/{
      localStorage.removeItem("".concat(this.storageName, ".").concat(key));
    }
  }]);
  return LocalStorage;
}();
;// CONCATENATED MODULE: ./src/sdk/smart-banner/storage/in-memory-storage.ts



var in_memory_storage_InMemoryStorage = /*#__PURE__*/function () {
  function InMemoryStorage() {
    _classCallCheck(this, InMemoryStorage);
    _defineProperty(this, "items", {});
  }
  _createClass(InMemoryStorage, [{
    key: "setItem",
    value: function setItem(key /*: string*/, value /*: any*/) /*: void*/{
      this.items[key] = value;
    }
  }, {
    key: "getItem",
    value: function getItem(key /*: string*/) /*: any | null*/{
      return Object.prototype.hasOwnProperty.call(this.items, key) ? this.items[key] : null;
    }
  }, {
    key: "removeItem",
    value: function removeItem(key /*: string*/) /*: void*/{
      delete this.items[key];
    }
  }]);
  return InMemoryStorage;
}();
;// CONCATENATED MODULE: ./src/sdk/smart-banner/storage/factory.ts





var StorageFactory = /*#__PURE__*/function () {
  function StorageFactory() {
    _classCallCheck(this, StorageFactory);
  }
  _createClass(StorageFactory, null, [{
    key: "isLocalStorageSupported",
    value: function isLocalStorageSupported() /*: boolean*/{
      try {
        var uid = new Date().toString();
        var storage = window.localStorage;
        storage.setItem(uid, uid);
        var result = storage.getItem(uid) === uid;
        storage.removeItem(uid);
        var support = !!(result && storage);
        return support;
      } catch (e) {
        return false;
      }
    }
  }, {
    key: "createStorage",
    value: function createStorage() /*: Storage*/{
      if (this.isLocalStorageSupported()) {
        return new LocalStorage();
      }
      return new in_memory_storage_InMemoryStorage();
    }
  }]);
  return StorageFactory;
}();

;// CONCATENATED MODULE: ./src/sdk/smart-banner/api.ts
var api_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;

var Position;
(function (Position) {
  Position["Top"] = "top";
  Position["Bottom"] = "bottom";
})(Position || (Position = {}));
/*:: export interface SmartBannerData {
  appId: string;
  appName: string;
  position: Position;
  imageUrl?: string;
  header: string;
  description: string;
  buttonText: string;
  dismissInterval: number;
  trackerToken: string;
  deeplinkPath?: string;
}*/
/**
 * Ensures response contains general info: title, description, button_label and tracker_token and converts response
 * to SmartBannerData
 */
function validate(response /*: Partial<SmartBannerResponse>*/) /*: SmartBannerData | null*/{
  var title = response.title,
    description = response.description,
    button_label = response.button_label,
    tracker_token = response.tracker_token;
  if (title && description && button_label && tracker_token) {
    var _response$app, _response$app2;
    return {
      appId: ((_response$app = response.app) === null || _response$app === void 0 ? void 0 : _response$app.default_store_app_id) || '',
      appName: ((_response$app2 = response.app) === null || _response$app2 === void 0 ? void 0 : _response$app2.name) || '',
      position: response.position || Position.Bottom,
      imageUrl: response.image_url,
      header: title,
      description: description,
      buttonText: button_label,
      trackerToken: tracker_token,
      deeplinkPath: response.deeplink_path,
      dismissInterval: 24 * 60 * 60 * 1000 // 1 day in millis before show banner next time
    };
  }

  return null;
}
function fetchSmartBannerData(webToken /*: string*/, deviceOs /*: DeviceOS*/, network /*: Network*/) /*: Promise<SmartBannerData | null>*/{
  var path = '/smart_banner';
  return network.request(path, {
    'app_web_token': webToken
  }).then(function (banners) {
    var banner = banners.find(function (item) {
      return item.platform === deviceOs;
    });
    if (!banner) {
      return null;
    }
    return validate(banner);
  }).catch(function (error) {
    sdk_logger.error('Network error occurred during loading Smart Banner: ' + JSON.stringify(error));
    return null;
  });
}
// EXTERNAL MODULE: ./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js
var injectStylesIntoStyleTag = __webpack_require__(3379);
var injectStylesIntoStyleTag_default = /*#__PURE__*/__webpack_require__.n(injectStylesIntoStyleTag);
// EXTERNAL MODULE: ./node_modules/style-loader/dist/runtime/styleDomAPI.js
var styleDomAPI = __webpack_require__(7795);
var styleDomAPI_default = /*#__PURE__*/__webpack_require__.n(styleDomAPI);
// EXTERNAL MODULE: ./node_modules/style-loader/dist/runtime/insertBySelector.js
var insertBySelector = __webpack_require__(569);
var insertBySelector_default = /*#__PURE__*/__webpack_require__.n(insertBySelector);
// EXTERNAL MODULE: ./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js
var setAttributesWithoutAttributes = __webpack_require__(3565);
var setAttributesWithoutAttributes_default = /*#__PURE__*/__webpack_require__.n(setAttributesWithoutAttributes);
// EXTERNAL MODULE: ./node_modules/style-loader/dist/runtime/insertStyleElement.js
var insertStyleElement = __webpack_require__(9216);
var insertStyleElement_default = /*#__PURE__*/__webpack_require__.n(insertStyleElement);
// EXTERNAL MODULE: ./node_modules/style-loader/dist/runtime/styleTagTransform.js
var styleTagTransform = __webpack_require__(4589);
var styleTagTransform_default = /*#__PURE__*/__webpack_require__.n(styleTagTransform);
// EXTERNAL MODULE: ./node_modules/css-loader/dist/cjs.js??ruleSet[1].rules[1].use[1]!./node_modules/sass-loader/dist/cjs.js!./src/sdk/smart-banner/assets/styles.module.scss
var styles_module = __webpack_require__(1841);
;// CONCATENATED MODULE: ./src/sdk/smart-banner/assets/styles.module.scss

      
      
      
      
      
      
      
      
      

var options = {};

options.styleTagTransform = (styleTagTransform_default());
options.setAttributes = (setAttributesWithoutAttributes_default());

      options.insert = insertBySelector_default().bind(null, "head");
    
options.domAPI = (styleDomAPI_default());
options.insertStyleElement = (insertStyleElement_default());

var update = injectStylesIntoStyleTag_default()(styles_module/* default */.Z, options);




       /* harmony default export */ const assets_styles_module = (styles_module/* default */.Z && styles_module/* default.locals */.Z.locals ? styles_module/* default.locals */.Z.locals : undefined);

;// CONCATENATED MODULE: ./src/sdk/smart-banner/assets/template.ts

/* harmony default export */ const template = (function (positionStyle /*: string*/, header /*: string*/, description /*: string*/, buttonText /*: string*/, href /*: string*/) {
  return "\n  <div class=\"".concat(assets_styles_module.banner, " ").concat(positionStyle, "\">\n    <div class=\"").concat(assets_styles_module.bannerBody, "\">\n      <div class=\"").concat(assets_styles_module.content, "\">\n        <button class=\"").concat(assets_styles_module.dismiss, "\"></button>\n        <div class=\"").concat(assets_styles_module.appIcon, "\">\n          <div class=\"").concat(assets_styles_module.placeholder, "\"></div>\n          <img class=\"").concat(assets_styles_module.image, "\" alt=\"").concat(header, "\">\n        </div>\n        <div class=\"").concat(assets_styles_module.textContainer, "\">\n          <h4 class=\"").concat(assets_styles_module.bannerText, "\">").concat(header, "</h4>\n          <p class=\"").concat(assets_styles_module.bannerText, "\">").concat(description, "</p>\n        </div>\n        <a class=\"").concat(assets_styles_module.action, "\" href=").concat(href, ">").concat(buttonText, "</a>\n      </div>\n    </div>\n  </div>");
});
;// CONCATENATED MODULE: ./src/sdk/smart-banner/view/app-icon.ts



var app_icon_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
var AppIcon = /*#__PURE__*/function () {
  function AppIcon(bannerData /*: AppIconData*/, image /*: HTMLImageElement*/, placeholder /*: HTMLElement*/) {
    _classCallCheck(this, AppIcon);
    _defineProperty(this, "appTraceUrl", function (appId /*: string*/) {
      return "https://www.apptrace.com/api/app/".concat(appId, "/artwork_url_small");
    });
    _defineProperty(this, "appName", void 0);
    _defineProperty(this, "image", void 0);
    _defineProperty(this, "placeholder", void 0);
    this.image = image;
    this.placeholder = placeholder;
    this.appName = bannerData.appName;
    var sources = this.getSources(bannerData);
    this.showImage(sources);
  }
  _createClass(AppIcon, [{
    key: "getSources",
    value: function getSources(bannerData /*: AppIconData*/) /*: string[]*/{
      var sourcesArray /*: string[]*/ = [];
      if (bannerData.imageUrl) {
        sourcesArray.push(bannerData.imageUrl);
      }
      sourcesArray.push(this.appTraceUrl(bannerData.appId));
      return sourcesArray;
    }
  }, {
    key: "showImage",
    value: function showImage(sources /*: string[]*/) /*: Promise<void>*/{
      var _this = this;
      var imageLoadingPromise = sources.reduce(function (acc, url) {
        return acc.catch(function () {
          return _this.loadImage(url, _this.image);
        });
      }, app_icon_Promise.reject());
      return imageLoadingPromise.then(function () {
        _this.placeholder.remove();
      }).catch(function () {
        _this.image.remove();
        _this.placeholder.innerText = _this.appName.length ? _this.appName[0].toUpperCase() : '';
      });
    }
  }, {
    key: "loadImage",
    value: function loadImage(url /*: string*/, image /*: HTMLImageElement*/) {
      return new app_icon_Promise(function (resolve, reject) {
        image.onload = resolve;
        image.onerror = reject;
        image.src = url;
      });
    }
  }]);
  return AppIcon;
}();
;// CONCATENATED MODULE: ./src/sdk/smart-banner/view/smart-banner-view.ts







var SmartBannerView = /*#__PURE__*/function () {
  function SmartBannerView(data /*: SmartBannerData*/, onDismiss /*: () => void*/, endpoint /*: string*/) {
    _classCallCheck(this, SmartBannerView);
    _defineProperty(this, "parent", document.body);
    _defineProperty(this, "banner", void 0);
    _defineProperty(this, "dismissButton", null);
    _defineProperty(this, "onDismiss", void 0);
    this.onDismiss = onDismiss;
    this.render(data, endpoint);
  }
  _createClass(SmartBannerView, [{
    key: "render",
    value: function render(bannerData /*: SmartBannerData*/, endpoint /*: string*/) {
      this.banner = document.createElement('div');
      this.banner.setAttribute('class', assets_styles_module.bannerContainer);
      var positionStyle = bannerData.position === Position.Top ? assets_styles_module.stickyToTop : assets_styles_module.stickyToBottom;
      var query = bannerData.deeplinkPath ? "?deeplink=".concat(encodeURIComponent(bannerData.deeplinkPath)) : '';
      var href = "".concat(endpoint, "/").concat(bannerData.trackerToken).concat(query);
      this.banner.innerHTML = template(positionStyle, bannerData.header, bannerData.description, bannerData.buttonText, href);
      if (bannerData.position === Position.Top) {
        this.parent.insertBefore(this.banner, this.parent.firstChild);
      } else {
        this.parent.appendChild(this.banner);
      }
      this.dismissButton = this.getElemByClass(assets_styles_module.dismiss);
      if (this.dismissButton) {
        this.dismissButton.addEventListener('click', this.onDismiss);
      }
      var appIconPlaceholder = this.getElemByClass(assets_styles_module.placeholder);
      var appIconImage = this.getElemByClass(assets_styles_module.image);
      if (appIconImage && appIconPlaceholder) {
        new AppIcon(bannerData, appIconImage, appIconPlaceholder);
      }
    }
  }, {
    key: "show",
    value: function show() {
      this.banner.hidden = false;
    }
  }, {
    key: "hide",
    value: function hide() {
      this.banner.hidden = true;
    }
  }, {
    key: "destroy",
    value: function destroy() {
      this.removeDismissButtonHandler();
      this.banner.remove();
    }
  }, {
    key: "removeDismissButtonHandler",
    value: function removeDismissButtonHandler() {
      if (this.dismissButton && this.onDismiss) {
        this.dismissButton.removeEventListener('click', this.onDismiss);
        this.dismissButton = null;
      }
    }
  }, {
    key: "getElemByClass",
    value: function getElemByClass /*:: <T extends Element>*/(classNames /*: string*/) /*: T | null*/{
      if (this.banner) {
        var elements = this.banner.getElementsByClassName(classNames);
        return elements.length > 0 ? elements[0] : null;
      }
      return null;
    }
  }]);
  return SmartBannerView;
}();
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/errors.ts
/*:: export interface NetworkError {
  status: number;
  message: string;
}*/
var NoConnectionError /*: NetworkError*/ = {
  status: 0,
  message: 'No internet connectivity'
};
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/xhr-network.ts



var xhr_network_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;



/** Sends HTTP GET request using XMLHttpRequest */
var XhrNetwork = /*#__PURE__*/function () {
  function XhrNetwork(origin /*: string*/) {
    _classCallCheck(this, XhrNetwork);
    this.origin /*:: ?*/ = origin /*:: ?*/;
  }
  _createClass(XhrNetwork, [{
    key: "endpoint",
    get: function get() /*: string*/{
      if (!this.origin) {
        throw Error('XhrNetwork: Origin not defined');
      }
      return this.origin;
    },
    set: function set(value /*: string*/) {
      this.origin = value;
    }

    /**
     * Creates an XMLHttpRequest object and sends a GET request with provided encoded URL
     * @param url encoded URL
     */
  }, {
    key: "xhr",
    value: function xhr /*:: <T>*/(url /*: string*/) /*: Promise<T>*/{
      return new xhr_network_Promise(function (resolve, reject /*: (err: NetworkError) => void*/) {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', url);
        var headers = [['Client-SDK', "js".concat(globals.version)], ['Content-Type', 'application/json']];
        headers.forEach(function (_ref) {
          var _ref2 = _slicedToArray(_ref, 2),
            key = _ref2[0],
            value = _ref2[1];
          xhr.setRequestHeader(key, value);
        });
        xhr.onerror = function () {
          return reject(NoConnectionError);
        };
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          var okStatus = xhr.status >= 200 && xhr.status < 300;
          var json = parseJson(xhr.responseText);
          if (xhr.status === 0) {
            reject(NoConnectionError);
          } else {
            if (okStatus) {
              resolve(json);
            } else {
              reject({
                status: xhr.status,
                message: json || xhr.responseText || ''
              });
            }
          }
        };
        xhr.send();
      });
    }
  }, {
    key: "encodeParams",
    value: function encodeParams(params /*: Record<string, Primitive>*/) /*: string*/{
      return Object.keys(params).map(function (key) {
        return [encodeURIComponent(key), encodeURIComponent(params[key])].join('=');
      }).join('&');
    }
  }, {
    key: "request",
    value: function request /*:: <T>*/(path /*: string*/, params /*: Record<string, Primitive>*/) /*: Promise<T>*/{
      var encodedParams = params ? "?".concat(this.encodeParams(params)) : '';
      return this.xhr("".concat(this.endpoint).concat(path).concat(encodedParams));
    }
  }]);
  return XhrNetwork;
}();
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/assertThisInitialized.js
function _assertThisInitialized(self) {
  if (self === void 0) {
    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
  }
  return self;
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/setPrototypeOf.js
function _setPrototypeOf(o, p) {
  _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function _setPrototypeOf(o, p) {
    o.__proto__ = p;
    return o;
  };
  return _setPrototypeOf(o, p);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/inherits.js

function _inherits(subClass, superClass) {
  if (typeof superClass !== "function" && superClass !== null) {
    throw new TypeError("Super expression must either be null or a function");
  }
  subClass.prototype = Object.create(superClass && superClass.prototype, {
    constructor: {
      value: subClass,
      writable: true,
      configurable: true
    }
  });
  Object.defineProperty(subClass, "prototype", {
    writable: false
  });
  if (superClass) _setPrototypeOf(subClass, superClass);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/getPrototypeOf.js
function _getPrototypeOf(o) {
  _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf.bind() : function _getPrototypeOf(o) {
    return o.__proto__ || Object.getPrototypeOf(o);
  };
  return _getPrototypeOf(o);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/isNativeReflectConstruct.js
function _isNativeReflectConstruct() {
  if (typeof Reflect === "undefined" || !Reflect.construct) return false;
  if (Reflect.construct.sham) return false;
  if (typeof Proxy === "function") return true;
  try {
    Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {}));
    return true;
  } catch (e) {
    return false;
  }
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/possibleConstructorReturn.js


function _possibleConstructorReturn(self, call) {
  if (call && (_typeof(call) === "object" || typeof call === "function")) {
    return call;
  } else if (call !== void 0) {
    throw new TypeError("Derived constructors may only return object or undefined");
  }
  return _assertThisInitialized(self);
}
;// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/createSuper.js



function _createSuper(Derived) {
  var hasNativeReflectConstruct = _isNativeReflectConstruct();
  return function _createSuperInternal() {
    var Super = _getPrototypeOf(Derived),
      result;
    if (hasNativeReflectConstruct) {
      var NewTarget = _getPrototypeOf(this).constructor;
      result = Reflect.construct(Super, arguments, NewTarget);
    } else {
      result = Super.apply(this, arguments);
    }
    return _possibleConstructorReturn(this, result);
  };
}
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/network.ts


var network_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: export interface Network {
  endpoint: string;
  request: <T>(path: string, params?: Record<string, string | number | boolean>) => Promise<T>;
}*/
var NetworkDecorator = /*#__PURE__*/function () {
  function NetworkDecorator(network /*: Network*/) {
    _classCallCheck(this, NetworkDecorator);
    this.network /*:: */ = network /*:: */;
  }
  _createClass(NetworkDecorator, [{
    key: "endpoint",
    get: function get() /*: string*/{
      return this.network.endpoint;
    },
    set: function set(value /*: string*/) {
      this.network.endpoint = value;
    }
  }, {
    key: "request",
    value: function request /*:: <T>*/(path /*: string*/, params /*: Record<string, string | number | boolean>*/) /*: Promise<T>*/{
      return this.network.request(path, params);
    }
  }]);
  return NetworkDecorator;
}();
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/url-strategy/url-strategy.ts



var url_strategy_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;


/*:: export type BaseUrlsMap = {
  endpointName: string;
  app: string;
  gdpr: string;
}*/
var UrlStrategy = /*#__PURE__*/function () {
  function UrlStrategy(preferredUrls /*: () => BaseUrlsMap[]*/) {
    _classCallCheck(this, UrlStrategy);
    this.preferredUrls /*:: */ = preferredUrls /*:: */;
  }

  /**
   * Gets the list of preferred endpoints and wraps `sendRequest` function with iterative retries until available
   * endpoint found or another error occurred.
   */
  _createClass(UrlStrategy, [{
    key: "retries",
    value: function retries /*:: <T>*/(sendRequest /*: (urls: BaseUrlsMap) => Promise<T>*/) /*: Promise<T>*/{
      var _this = this;
      var attempt = 0;
      var trySendRequest = function trySendRequest() /*: Promise<T>*/{
        var preferredUrls = _this.preferredUrls();
        if (!preferredUrls || preferredUrls.length === 0) {
          sdk_logger.error(UrlStrategy.NoPreferredUrlsDefinedError.message);
          throw UrlStrategy.NoPreferredUrlsDefinedError;
        }
        var urlsMap = preferredUrls[attempt++];
        return sendRequest(urlsMap).catch(function (reason /*: NetworkError*/) {
          if (reason === NoConnectionError) {
            sdk_logger.log("Failed to connect ".concat(urlsMap.endpointName, " endpoint"));
            if (attempt < preferredUrls.length) {
              sdk_logger.log("Trying ".concat(preferredUrls[attempt].endpointName, " one"));
              return trySendRequest(); // Trying next endpoint
            }
          }

          // Another error occurred or we ran out of attempts, re-throw
          throw reason;
        });
      };
      return trySendRequest();
    }
  }]);
  return UrlStrategy;
}();
_defineProperty(UrlStrategy, "NoPreferredUrlsDefinedError", new ReferenceError('UrlStrategy: No preferred URL defined'));
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/url-strategy/blocked-url-bypass.ts


var BlockedUrlBypass;
(function (_BlockedUrlBypass) {
  var _endpoints;
  var Default = _BlockedUrlBypass.Default = 'default';
  var India = _BlockedUrlBypass.India = 'india';
  var China = _BlockedUrlBypass.China = 'china';
  /*:: */
  var endpoints /*:: */ = (_endpoints = {}, _defineProperty(_endpoints, BlockedUrlBypass.Default, ENDPOINTS["default"]), _defineProperty(_endpoints, BlockedUrlBypass.India, ENDPOINTS.india), _defineProperty(_endpoints, BlockedUrlBypass.China, ENDPOINTS.china), _endpoints);
  var getPreferredUrlsWithOption = function getPreferredUrlsWithOption(endpoints /*:: */, option /*:: */) {
    if (option === BlockedUrlBypass.India) {
      return [endpoints[BlockedUrlBypass.India], endpoints[BlockedUrlBypass.Default]];
    }
    if (option === BlockedUrlBypass.China) {
      return [endpoints[BlockedUrlBypass.China], endpoints[BlockedUrlBypass.Default]];
    }
    return [endpoints[BlockedUrlBypass.Default], endpoints[BlockedUrlBypass.India], endpoints[BlockedUrlBypass.China]];
  };
  function preferredUrlsGetter(option /*:: */) {
    var endpointsMap /*:: */ = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : endpoints;
    return function () {
      return getPreferredUrlsWithOption(endpointsMap, option);
    };
  }
  _BlockedUrlBypass.preferredUrlsGetter = preferredUrlsGetter;
})(BlockedUrlBypass || (BlockedUrlBypass = {}));
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/url-strategy/custom-url.ts
var CustomUrl;
(function (_CustomUrl) {
  var getPreferredUrlsWithOption = function getPreferredUrlsWithOption(customUrl /*:: */) {
    return [{
      endpointName: "Custom (".concat(customUrl, ")"),
      app: customUrl,
      gdpr: customUrl
    }];
  };
  function preferredUrlsGetter(customUrl /*:: */) {
    return function () {
      return getPreferredUrlsWithOption(customUrl);
    };
  }
  _CustomUrl.preferredUrlsGetter = preferredUrlsGetter;
})(CustomUrl || (CustomUrl = {}));
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/url-strategy/data-residency.ts


var DataResidency;
(function (_DataResidency) {
  var _endpoints;
  var EU = _DataResidency.EU = 'EU';
  var TR = _DataResidency.TR = 'TR';
  var US = _DataResidency.US = 'US';
  /*:: */
  var endpoints /*:: */ = (_endpoints = {}, _defineProperty(_endpoints, DataResidency.EU, ENDPOINTS.EU), _defineProperty(_endpoints, DataResidency.TR, ENDPOINTS.TR), _defineProperty(_endpoints, DataResidency.US, ENDPOINTS.US), _endpoints);
  var getPreferredUrlsWithOption = function getPreferredUrlsWithOption(endpoints /*:: */, option /*:: */) {
    return [endpoints[option]];
  };
  function preferredUrlsGetter(option /*:: */) {
    var endpointsMap /*:: */ = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : endpoints;
    return function () {
      return getPreferredUrlsWithOption(endpointsMap, option);
    };
  }
  _DataResidency.preferredUrlsGetter = preferredUrlsGetter;
})(DataResidency || (DataResidency = {}));
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/url-strategy/url-strategy-factory.ts





/*:: export type UrlStrategyConfig = {
  customUrl: string;
  urlStrategy?: never;
  dataResidency?: never;
} | {
  customUrl?: never;
  dataResidency: DataResidency.Region;
  urlStrategy?: never;
} | {
  customUrl?: never;
  dataResidency?: never;
  urlStrategy?: BlockedUrlBypass.Strategy;
}*/
var UrlStrategyFactory;
(function (_UrlStrategyFactory) {
  var incorrectOptionIgnoredMessage = function incorrectOptionIgnoredMessage(higherPriority /*:: */, lowerPriority /*:: */) {
    sdk_logger.warn("Both ".concat(higherPriority, " and ").concat(lowerPriority, " are set in config, ").concat(lowerPriority, " will be ignored"));
  };
  function create(config /*:: */) /*:: */{
    var customUrl = config.customUrl,
      dataResidency = config.dataResidency,
      urlStrategy = config.urlStrategy;
    if (customUrl) {
      if (dataResidency || urlStrategy) {
        incorrectOptionIgnoredMessage('customUrl', dataResidency ? 'dataResidency' : 'urlStrategy');
      }
      return new UrlStrategy(CustomUrl.preferredUrlsGetter(customUrl));
    } else if (dataResidency) {
      if (urlStrategy) {
        incorrectOptionIgnoredMessage('dataResidency', 'urlStrategy');
      }
      return new UrlStrategy(DataResidency.preferredUrlsGetter(dataResidency));
    } else {
      return new UrlStrategy(BlockedUrlBypass.preferredUrlsGetter(urlStrategy));
    }
  }
  _UrlStrategyFactory.create = create;
})(UrlStrategyFactory || (UrlStrategyFactory = {}));
;// CONCATENATED MODULE: ./src/sdk/smart-banner/network/url-startegy-network.ts






var url_startegy_network_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;



var NetworkWithUrlStrategy = /*#__PURE__*/function (_NetworkDecorator) {
  _inherits(NetworkWithUrlStrategy, _NetworkDecorator);
  var _super = _createSuper(NetworkWithUrlStrategy);
  function NetworkWithUrlStrategy(network /*: Network*/, _ref /*:: */) {
    var _this;
    var urlStrategy = _ref /*:: */.urlStrategy,
      urlStrategyConfig = _ref /*:: */.urlStrategyConfig;
    _classCallCheck(this, NetworkWithUrlStrategy);
    _this = _super.call(this, network);
    _defineProperty(_assertThisInitialized(_this), "lastSuccessfulEndpoint", void 0);
    _defineProperty(_assertThisInitialized(_this), "urlStrategy", void 0);
    _this.urlStrategy = urlStrategy || UrlStrategyFactory.create(urlStrategyConfig);
    return _this;
  }

  /**
   * Returns last succesfull endpoint or default (`https://app.wisetrack.com`) one
   */
  _createClass(NetworkWithUrlStrategy, [{
    key: "endpoint",
    get: function get() /*: string*/{
      return this.lastSuccessfulEndpoint || NetworkWithUrlStrategy.DEFAULT_ENDPOINT;
    }

    /**
     * Sends a request to provided path choosing origin with UrlStrategy and caches used origin if it was successfully
     * reached
     *
     * @param path
     * @param params non-encoded parameters of the request
     */
  }, {
    key: "request",
    value: function request /*:: <T>*/(path /*: string*/, params /*: Record<string, string | number | boolean>*/) /*: Promise<T>*/{
      var _this2 = this;
      return this.urlStrategy.retries(function (baseUrlsMap) {
        _this2.network.endpoint = baseUrlsMap.app;
        return _this2.network.request(path, params).then(function (result /*: T*/) {
          _this2.lastSuccessfulEndpoint = baseUrlsMap.app;
          return result;
        }).catch(function (err /*: NetworkError*/) {
          _this2.lastSuccessfulEndpoint = undefined;
          throw err;
        });
      });
    }
  }]);
  return NetworkWithUrlStrategy;
}(NetworkDecorator);
_defineProperty(NetworkWithUrlStrategy, "DEFAULT_ENDPOINT", ENDPOINTS["default"].app);
(function (_NetworkWithUrlStrategy) {
  /*:: */
})(NetworkWithUrlStrategy || (NetworkWithUrlStrategy = {}));
;// CONCATENATED MODULE: ./src/sdk/smart-banner/smart-banner.ts



var smart_banner_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;







/**
 * WiseTrack Web SDK Smart Banner
 */
var SmartBanner = /*#__PURE__*/function () {
  function SmartBanner(_ref /*:: */, network /*: Network*/) {
    var webToken = _ref /*:: */.webToken,
      _ref$logLevel = _ref /*:: */.logLevel,
      logLevel = _ref$logLevel === void 0 ? 'error' : _ref$logLevel,
      dataResidency = _ref /*:: */.dataResidency,
      onCreated = _ref /*:: */.onCreated,
      onDismissed = _ref /*:: */.onDismissed;
    _classCallCheck(this, SmartBanner);
    _defineProperty(this, "STORAGE_KEY_DISMISSED", 'closed');
    _defineProperty(this, "network", void 0);
    _defineProperty(this, "storage", void 0);
    _defineProperty(this, "timer", null);
    _defineProperty(this, "dataFetchPromise", void 0);
    _defineProperty(this, "banner", void 0);
    _defineProperty(this, "onCreated", void 0);
    _defineProperty(this, "onDismissed", void 0);
    this.onCreated = onCreated;
    this.onDismissed = onDismissed;
    sdk_logger.setLogLevel(logLevel);
    var config = dataResidency ? {
      dataResidency: dataResidency
    } : {};
    this.network = network || new NetworkWithUrlStrategy(new XhrNetwork(), {
      urlStrategyConfig: config
    });
    this.storage = StorageFactory.createStorage();
    this.init(webToken);
  }

  /**
   * Initiate Smart Banner
   *
   * @param webToken token used to get data from backend
   */
  _createClass(SmartBanner, [{
    key: "init",
    value: function init(webToken /*: string*/) {
      var _this = this;
      if (this.banner) {
        sdk_logger.error('Smart Banner already exists');
        return;
      }
      if (this.dataFetchPromise) {
        sdk_logger.error('Smart Banner is initialising already');
        return;
      }
      var deviceOs = getDeviceOS();
      if (!deviceOs) {
        sdk_logger.log('This platform is not one of the targeting ones, Smart Banner will not be shown');
        return;
      }
      this.dataFetchPromise = fetchSmartBannerData(webToken, deviceOs, this.network);
      this.dataFetchPromise.then(function (bannerData) {
        _this.dataFetchPromise = null;
        if (!bannerData) {
          sdk_logger.log("No Smart Banners for ".concat(deviceOs, " platform found"));
          return;
        }
        var whenToShow = _this.getDateToShowAgain(bannerData.dismissInterval);
        if (Date.now() < whenToShow) {
          sdk_logger.log('Smart Banner was dismissed');
          _this.scheduleCreation(webToken, whenToShow);
          return;
        }
        sdk_logger.log('Creating Smart Banner');
        _this.banner = new SmartBannerView(bannerData, function () {
          return _this.dismiss(webToken, bannerData.dismissInterval);
        }, _this.network.endpoint);
        sdk_logger.log('Smart Banner created');
        if (_this.onCreated) {
          _this.onCreated();
        }
      });
    }

    /**
     * Show Smart Banner
     */
  }, {
    key: "show",
    value: function show() /*: void*/{
      var _this2 = this;
      if (this.banner) {
        this.banner.show();
        return;
      }
      if (this.dataFetchPromise) {
        sdk_logger.log('Smart Banner will be shown after initialisation finished');
        this.dataFetchPromise.then(function () {
          sdk_logger.log('Initialisation finished, showing Smart Banner');
          _this2.show();
        });
        return;
      }
      sdk_logger.error('There is no Smart Banner to show, have you called initialisation?');
    }

    /**
     * Hide Smart Banner
     */
  }, {
    key: "hide",
    value: function hide() /*: void*/{
      var _this3 = this;
      if (this.banner) {
        this.banner.hide();
        return;
      }
      if (this.dataFetchPromise) {
        sdk_logger.log('Smart Banner will be hidden after initialisation finished');
        this.dataFetchPromise.then(function () {
          sdk_logger.log('Initialisation finished, hiding Smart Banner');
          _this3.hide();
        });
        return;
      }
      sdk_logger.error('There is no Smart Banner to hide, have you called initialisation?');
    }

    /**
     * Removes Smart Banner from DOM
     */
  }, {
    key: "destroy",
    value: function destroy() {
      if (this.banner) {
        this.banner.destroy();
        this.banner = null;
        sdk_logger.log('Smart Banner removed');
      } else {
        sdk_logger.error('There is no Smart Banner to remove');
      }
    }

    /**
     * Schedules next Smart Banner show and removes banner from DOM
     */
  }, {
    key: "dismiss",
    value: function dismiss(webToken /*: string*/, dismissInterval /*: number*/) {
      sdk_logger.log('Smart Banner dismissed');
      this.storage.setItem(this.STORAGE_KEY_DISMISSED, Date.now());
      var whenToShow = this.getDateToShowAgain(dismissInterval);
      this.scheduleCreation(webToken, whenToShow);
      this.destroy();
      if (this.onDismissed) {
        this.onDismissed();
      }
    }

    /**
     * Sets a timeout to schedule next Smart Banner show
     */
  }, {
    key: "scheduleCreation",
    value: function scheduleCreation(webToken /*: string*/, when /*: number*/) {
      var _this4 = this;
      if (this.timer) {
        sdk_logger.log('Clearing previously scheduled creation of Smart Banner');
        clearTimeout(this.timer);
        this.timer = null;
      }
      var delay = when - Date.now();
      this.timer = setTimeout(function () {
        _this4.timer = null;
        _this4.init(webToken);
      }, delay);
      sdk_logger.log('Smart Banner creation scheduled on ' + new Date(when));
    }

    /**
     * Returns date when Smart Banner should be shown again
     */
  }, {
    key: "getDateToShowAgain",
    value: function getDateToShowAgain(dismissInterval /*: number*/) /*: number*/{
      var dismissedDate = this.storage.getItem(this.STORAGE_KEY_DISMISSED);
      if (!dismissedDate || typeof dismissedDate !== 'number') {
        return Date.now();
      }
      return dismissedDate + dismissInterval;
    }
  }]);
  return SmartBanner;
}();
;// CONCATENATED MODULE: ./src/sdk/config-api-request.js




var url = 'https://config.wisetrack.io';
var body;
var isInitialized = false;
var first_launch_key = 'first_launch_key';
var sdk_configs_key = 'sdk_configs_key';
var config_api_request_config /*: PrimitiveConfigT*/;

// Function to initialize the configuration or any setup tasks
function config_api_request_init() {
  initI();
  if (isInitialized) return;
  isInitialized = true;
  constants_configs.CONFIG_API_HTTP_ERROR_STATUS = false;
  constants_configs.HTTP_STATUS_CODE = 200;
  constants_configs.app_settings_enabled = false;
}
function initI() {
  if (isFirstLaunch()) {
    localStorage.setItem(sdk_configs_key, JSON.stringify(initDefaultConfig));
    localStorage.setItem(first_launch_key, true);
  }
}
function initDefaultConfig() /*: PrimitiveConfigT*/{
  return {
    eventUrl: '/api/v13/events',
    sessionUrl: '/api/v1555/sessions',
    sdkClickUrl: '/api/v1/sdk_clicks',
    sdkInfosUrl: '/api/v1/sdk_infos',
    AttributionUrl: '/api/v1/attributions',
    packageInfoUrl: '/api/v1/package-info',
    appSettingUrl: '/api/v1/app_settings',
    pageUrl: '/api/v1/pages',
    baseUrl: 'https://core.wisetrack.io',
    sdkSecure: true,
    sdkEnabled: false,
    sentryEnabled: true,
    forceUpdate: false,
    sdkUpdate: false,
    sessionInterval: '1800' // second
  };
}

function isFirstLaunch() /*: Boolean*/{
  if (localStorage.getItem(first_launch_key) == null) {
    return true;
  } else {
    return false;
  }
}
function sendRequest() {
  return _sendRequest.apply(this, arguments);
}
function _sendRequest() {
  _sendRequest = asyncToGenerator_asyncToGenerator( /*#__PURE__*/regeneratorRuntime_regeneratorRuntime().mark(function _callee() {
    var response, responseData;
    return regeneratorRuntime_regeneratorRuntime().wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.prev = 0;
            _context.next = 3;
            return fetch(url, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify(body) // Sending the body as JSON
            });
          case 3:
            response = _context.sent;
            // Step 2: Check if the response is successful
            if (!response.ok) {
              error(response.status);
            }

            // Step 3: Parse the JSON response
            _context.next = 7;
            return response.json();
          case 7:
            responseData = _context.sent;
            console.log('API Response:', responseData);
            if (responseData.success && responseData.result) {
              success(responseData);
            }
            _context.next = 17;
            break;
          case 12:
            _context.prev = 12;
            _context.t0 = _context["catch"](0);
            constants_configs.CONFIG_API_HTTP_ERROR_STATUS = true;
            constants_configs.HTTP_STATUS_CODE = 404;
            console.error('API call failed:', _context.t0);
          case 17:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, null, [[0, 12]]);
  }));
  return _sendRequest.apply(this, arguments);
}
function config_api_request_parser(result) {
  var events = result.events,
    sessions = result.sessions,
    sdk_clicks = result.sdk_clicks,
    sdk_infos = result.sdk_infos,
    attributions = result.attributions,
    pkg_info = result.pkg_info,
    app_settings = result.app_settings,
    base_url = result.base_url,
    sdk_enabled = result.sdk_enabled,
    sentry_enabled = result.sentry_enabled,
    session_interval = result.session_interval,
    sdk_update = result.sdk_update,
    force_update = result.force_update;
  if (app_settings != null) {
    if (app_settings.length > 0) {
      constants_configs.app_settings_enabled = true;
    } else {
      config_api_request_config = {
        eventUrl: events,
        sessionUrl: sessions,
        sdkClickUrl: sdk_clicks,
        sdkInfosUrl: sdk_infos,
        AttributionUrl: attributions,
        packageInfoUrl: pkg_info,
        appSettingUrl: app_settings,
        pageUrl: '/api/v1/pages',
        baseUrl: base_url,
        sdkSecure: true,
        sdkEnabled: sdk_enabled,
        sentryEnabled: sentry_enabled,
        forceUpdate: force_update,
        sdkUpdate: sdk_update,
        sessionInterval: session_interval // milisecond, but convert to second
      };
    }
  } else {
    config_api_request_config = {
      eventUrl: events,
      sessionUrl: sessions,
      sdkClickUrl: sdk_clicks,
      sdkInfosUrl: sdk_infos,
      AttributionUrl: attributions,
      packageInfoUrl: pkg_info,
      appSettingUrl: '',
      pageUrl: '/api/v1/pages',
      baseUrl: base_url,
      sdkSecure: true,
      sdkEnabled: sdk_enabled,
      sentryEnabled: sentry_enabled,
      forceUpdate: force_update,
      sdkUpdate: sdk_update,
      sessionInterval: session_interval // milisecond, but convert to second
    };
  }

  localStorage.setItem(sdk_configs_key, JSON.stringify(config_api_request_config));
}
function success(responseData) {
  config_api_request_parser(responseData.result);
  setConfigs();
}
function error(status) {
  constants_configs.CONFIG_API_HTTP_ERROR_STATUS = true;
  constants_configs.HTTP_STATUS_CODE = status;
  setConfigs();
  throw new Error("HTTP error! Status: ".concat(status));
}
function setConfigs() {
  var storedConfig = localStorage.getItem(sdk_configs_key);
  if (storedConfig) {
    var parsedConfig /*: PrimitiveConfigT*/ = JSON.parse(storedConfig);
    constants_configs.events = parsedConfig.eventUrl;
    constants_configs.sessions = parsedConfig.sessionUrl;
    constants_configs.sdk_clicks = parsedConfig.sdkClickUrl;
    constants_configs.sdk_infos = parsedConfig.sdkInfosUrl;
    constants_configs.attributions = parsedConfig.AttributionUrl;
    constants_configs.pkg_info = parsedConfig.packageInfoUrl;
    constants_configs.app_settings = parsedConfig.appSettingUrl;
    constants_configs.base_url = parsedConfig.baseUrl;
    constants_configs.sdk_enabled = parsedConfig.sdkEnabled;
    constants_configs.sentry_enabled = parsedConfig.sentryEnabled;
    constants_configs.session_interval = parsedConfig.sessionInterval;
    constants_configs.sdk_update = parsedConfig.sdkUpdate;
    constants_configs.force_update = parsedConfig.forceUpdate;
    console.log(parsedConfig);
  }
}
function sendConfig(_x) {
  return _sendConfig.apply(this, arguments);
}
function _sendConfig() {
  _sendConfig = asyncToGenerator_asyncToGenerator( /*#__PURE__*/regeneratorRuntime_regeneratorRuntime().mark(function _callee2(versionConfig) {
    return regeneratorRuntime_regeneratorRuntime().wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            config_api_request_init();
            body = {
              env: versionConfig.sdkEnvirment,
              sdk_version: versionConfig.sdkVersion,
              sdk_hash: versionConfig.sdkHashBuild,
              sdk_platform: versionConfig.sdkPlatform
            };
            _context2.next = 4;
            return sendRequest();
          case 4:
          case "end":
            return _context2.stop();
        }
      }
    }, _callee2);
  }));
  return _sendConfig.apply(this, arguments);
}
;// CONCATENATED MODULE: ./src/sdk/version-config.js
function getConfig(platform, env) /*: VersionConfigParamsT*/{
  switch (platform) {
    case PlatformType.WEB:
      switch (env) {
        case EnvirmentType.DEBUG:
          return {
            sdkVersion: '0.9.0-alpha',
            sdkVersionCode: '20',
            sdkHashBuild: 'ae58c3f730f0629ca90d1a401ff6db164a2d5d2d5ey5e5et5er3131cffe25a5f1c',
            sdkPlatform: 'web',
            sdkEnvirment: 'debug'
          };
        case EnvirmentType.STAGE:
          return {
            sdkVersion: '0.9.0-alpha',
            sdkVersionCode: '20',
            sdkHashBuild: 'ae58c3f730f0629ca90d1a401ff6db164a2d5d2d5ey5e5et5er3131cffe25a5f1c',
            sdkPlatform: 'web',
            sdkEnvirment: 'stage'
          };
        case EnvirmentType.PRODUCTION:
          return {
            sdkVersion: '0.9.0-alpha',
            sdkVersionCode: '20',
            sdkHashBuild: 'ae58c3f730f0629ca90d1a401ff6db164a2d5d2d5ey5e5et5er3131cffe25a5f1c',
            sdkPlatform: 'web',
            sdkEnvirment: 'production'
          };
      }
      break;
    case PlatformType.PWA:
      this.sdk_version = '';
      this.sdk_version_code = '';
      this.sdk_hash_Build = '';
      this.sdk_platform = 'pwa';
      this.sdk_envirment = 'debug';
      break;
    default:
      throw new Error('Unknown platform type');
  }
}
/*:: export type VersionConfigParamsT = {|
  sdkVersion: string,
  sdkVersionCode: string,
  sdkHashBuild: string,
  sdkPlatform: string,
  sdkEnvirment: string,
|}*/
// Enum for EnvirmentType
var EnvirmentType = {
  PRODUCTION: {
    displayName: 'production'
  },
  STAGE: {
    displayName: 'stage'
  },
  DEBUG: {
    displayName: 'debug'
  }
};

// Enum for PlatformType with only WEB and PWA
var PlatformType = {
  WEB: 'WEB',
  PWA: 'PWA'
};

// const config = new VersionConfig(PlatformType.WEB, EnvirmentType.PRODUCTION);
// console.log(config);

//Export the VersionConfig class and enums for use in other files
//export { VersionConfig, PlatformType, EnvirmentType}
;// CONCATENATED MODULE: ./src/sdk/app-setting-api-request.js



function callSettingsApi(_x) {
  return _callSettingsApi.apply(this, arguments);
}
function _callSettingsApi() {
  _callSettingsApi = asyncToGenerator_asyncToGenerator( /*#__PURE__*/regeneratorRuntime_regeneratorRuntime().mark(function _callee(appToken) {
    var url, body, response, responseData, result, session_interval, sessionInterval;
    return regeneratorRuntime_regeneratorRuntime().wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            url = constants_configs.base_url + constants_configs.app_settings;
            body = {
              app_token: appToken
            };
            _context.prev = 2;
            _context.next = 5;
            return fetch(url, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify(body)
            });
          case 5:
            response = _context.sent;
            if (response.ok) {
              _context.next = 8;
              break;
            }
            throw new Error("HTTP error! Status: ".concat(response.status));
          case 8:
            _context.next = 10;
            return response.json();
          case 10:
            responseData = _context.sent;
            if (responseData.success && responseData.result) {
              result = responseData.result;
              session_interval = result.session_interval;
              if (session_interval != null) {
                sessionInterval = Number(session_interval);
                sessionInterval = sessionInterval / 1000; // convert milis to second
                constants_configs.session_interval = sessionInterval;
              } else {
                constants_configs.session_interval = '1800';
              }
            }
            _context.next = 17;
            break;
          case 14:
            _context.prev = 14;
            _context.t0 = _context["catch"](2);
            console.error('API call failed:', _context.t0);
          case 17:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, null, [[2, 14]]);
  }));
  return _callSettingsApi.apply(this, arguments);
}
;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/debug-build.js
/**
 * This serves as a build time flag that will be true by default, but false in non-debug builds or if users replace `__SENTRY_DEBUG__` in their generated code.
 *
 * ATTENTION: This constant must never cross package boundaries (i.e. be exported) to guarantee that it can be used for tree shaking.
 */
const debug_build_DEBUG_BUILD = (typeof __SENTRY_DEBUG__ === 'undefined' || __SENTRY_DEBUG__);


//# sourceMappingURL=debug-build.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/debug-build.js
/**
 * This serves as a build time flag that will be true by default, but false in non-debug builds or if users replace `__SENTRY_DEBUG__` in their generated code.
 *
 * ATTENTION: This constant must never cross package boundaries (i.e. be exported) to guarantee that it can be used for tree shaking.
 */
const utils_hoist_debug_build_DEBUG_BUILD = (typeof __SENTRY_DEBUG__ === 'undefined' || __SENTRY_DEBUG__);


//# sourceMappingURL=debug-build.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/version.js
// This is a magic string replaced by rollup

const SDK_VERSION = "8.46.0" ;


//# sourceMappingURL=version.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/worldwide.js


/** Get's the global object for the current JavaScript runtime */
const worldwide_GLOBAL_OBJ = globalThis ;

/**
 * Returns a global singleton contained in the global `__SENTRY__[]` object.
 *
 * If the singleton doesn't already exist in `__SENTRY__`, it will be created using the given factory
 * function and added to the `__SENTRY__` object.
 *
 * @param name name of the global singleton on __SENTRY__
 * @param creator creator Factory function to create the singleton if it doesn't already exist on `__SENTRY__`
 * @param obj (Optional) The global object on which to look for `__SENTRY__`, if not `GLOBAL_OBJ`'s return value
 * @returns the singleton
 */
function getGlobalSingleton(name, creator, obj) {
  const gbl = (obj || worldwide_GLOBAL_OBJ) ;
  const __SENTRY__ = (gbl.__SENTRY__ = gbl.__SENTRY__ || {});
  const versionedCarrier = (__SENTRY__[SDK_VERSION] = __SENTRY__[SDK_VERSION] || {});
  return versionedCarrier[name] || (versionedCarrier[name] = creator());
}


//# sourceMappingURL=worldwide.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/logger.js



/** Prefix for logging strings */
const PREFIX = 'Sentry Logger ';

const CONSOLE_LEVELS = [
  'debug',
  'info',
  'warn',
  'error',
  'log',
  'assert',
  'trace',
] ;

/** This may be mutated by the console instrumentation. */
const originalConsoleMethods

 = {};

/** JSDoc */

/**
 * Temporarily disable sentry console instrumentations.
 *
 * @param callback The function to run against the original `console` messages
 * @returns The results of the callback
 */
function consoleSandbox(callback) {
  if (!("console" in worldwide_GLOBAL_OBJ)) {
    return callback();
  }

  const console = worldwide_GLOBAL_OBJ.console ;
  const wrappedFuncs = {};

  const wrappedLevels = Object.keys(originalConsoleMethods) ;

  // Restore all wrapped console methods
  wrappedLevels.forEach(level => {
    const originalConsoleMethod = originalConsoleMethods[level] ;
    wrappedFuncs[level] = console[level] ;
    console[level] = originalConsoleMethod;
  });

  try {
    return callback();
  } finally {
    // Revert restoration to wrapped state
    wrappedLevels.forEach(level => {
      console[level] = wrappedFuncs[level] ;
    });
  }
}

function makeLogger() {
  let enabled = false;
  const logger = {
    enable: () => {
      enabled = true;
    },
    disable: () => {
      enabled = false;
    },
    isEnabled: () => enabled,
  };

  if (utils_hoist_debug_build_DEBUG_BUILD) {
    CONSOLE_LEVELS.forEach(name => {
      logger[name] = (...args) => {
        if (enabled) {
          consoleSandbox(() => {
            worldwide_GLOBAL_OBJ.console[name](`${PREFIX}[${name}]:`, ...args);
          });
        }
      };
    });
  } else {
    CONSOLE_LEVELS.forEach(name => {
      logger[name] = () => undefined;
    });
  }

  return logger ;
}

/**
 * This is a logger singleton which either logs things or no-ops if logging is not enabled.
 * The logger is a singleton on the carrier, to ensure that a consistent logger is used throughout the SDK.
 */
const logger_logger = getGlobalSingleton('logger', makeLogger);


//# sourceMappingURL=logger.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/integration.js




const installedIntegrations = [];

/** Map of integrations assigned to a client */

/**
 * Remove duplicates from the given array, preferring the last instance of any duplicate. Not guaranteed to
 * preserve the order of integrations in the array.
 *
 * @private
 */
function filterDuplicates(integrations) {
  const integrationsByName = {};

  integrations.forEach((currentInstance) => {
    const { name } = currentInstance;

    const existingInstance = integrationsByName[name];

    // We want integrations later in the array to overwrite earlier ones of the same type, except that we never want a
    // default instance to overwrite an existing user instance
    if (existingInstance && !existingInstance.isDefaultInstance && currentInstance.isDefaultInstance) {
      return;
    }

    integrationsByName[name] = currentInstance;
  });

  return Object.values(integrationsByName);
}

/** Gets integrations to install */
function getIntegrationsToSetup(options) {
  const defaultIntegrations = options.defaultIntegrations || [];
  const userIntegrations = options.integrations;

  // We flag default instances, so that later we can tell them apart from any user-created instances of the same class
  defaultIntegrations.forEach((integration) => {
    integration.isDefaultInstance = true;
  });

  let integrations;

  if (Array.isArray(userIntegrations)) {
    integrations = [...defaultIntegrations, ...userIntegrations];
  } else if (typeof userIntegrations === 'function') {
    const resolvedUserIntegrations = userIntegrations(defaultIntegrations);
    integrations = Array.isArray(resolvedUserIntegrations) ? resolvedUserIntegrations : [resolvedUserIntegrations];
  } else {
    integrations = defaultIntegrations;
  }

  const finalIntegrations = filterDuplicates(integrations);

  // The `Debug` integration prints copies of the `event` and `hint` which will be passed to `beforeSend` or
  // `beforeSendTransaction`. It therefore has to run after all other integrations, so that the changes of all event
  // processors will be reflected in the printed values. For lack of a more elegant way to guarantee that, we therefore
  // locate it and, assuming it exists, pop it out of its current spot and shove it onto the end of the array.
  const debugIndex = finalIntegrations.findIndex(integration => integration.name === 'Debug');
  if (debugIndex > -1) {
    const [debugInstance] = finalIntegrations.splice(debugIndex, 1) ;
    finalIntegrations.push(debugInstance);
  }

  return finalIntegrations;
}

/**
 * Given a list of integration instances this installs them all. When `withDefaults` is set to `true` then all default
 * integrations are added unless they were already provided before.
 * @param integrations array of integration instances
 * @param withDefault should enable default integrations
 */
function setupIntegrations(client, integrations) {
  const integrationIndex = {};

  integrations.forEach(integration => {
    // guard against empty provided integrations
    if (integration) {
      setupIntegration(client, integration, integrationIndex);
    }
  });

  return integrationIndex;
}

/**
 * Execute the `afterAllSetup` hooks of the given integrations.
 */
function afterSetupIntegrations(client, integrations) {
  for (const integration of integrations) {
    // guard against empty provided integrations
    if (integration && integration.afterAllSetup) {
      integration.afterAllSetup(client);
    }
  }
}

/** Setup a single integration.  */
function setupIntegration(client, integration, integrationIndex) {
  if (integrationIndex[integration.name]) {
    debug_build_DEBUG_BUILD && logger_logger.log(`Integration skipped because it was already installed: ${integration.name}`);
    return;
  }
  integrationIndex[integration.name] = integration;

  // `setupOnce` is only called the first time
  if (installedIntegrations.indexOf(integration.name) === -1 && typeof integration.setupOnce === 'function') {
    integration.setupOnce();
    installedIntegrations.push(integration.name);
  }

  // `setup` is run for each client
  if (integration.setup && typeof integration.setup === 'function') {
    integration.setup(client);
  }

  if (typeof integration.preprocessEvent === 'function') {
    const callback = integration.preprocessEvent.bind(integration) ;
    client.on('preprocessEvent', (event, hint) => callback(event, hint, client));
  }

  if (typeof integration.processEvent === 'function') {
    const callback = integration.processEvent.bind(integration) ;

    const processor = Object.assign((event, hint) => callback(event, hint, client), {
      id: integration.name,
    });

    client.addEventProcessor(processor);
  }

  debug_build_DEBUG_BUILD && logger_logger.log(`Integration installed: ${integration.name}`);
}

/** Add an integration to the current scope's client. */
function addIntegration(integration) {
  const client = getClient();

  if (!client) {
    DEBUG_BUILD && logger.warn(`Cannot add integration "${integration.name}" because no SDK Client is available.`);
    return;
  }

  client.addIntegration(integration);
}

/**
 * Define an integration function that can be used to create an integration instance.
 * Note that this by design hides the implementation details of the integration, as they are considered internal.
 */
function defineIntegration(fn) {
  return fn;
}


//# sourceMappingURL=integration.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/is.js
// eslint-disable-next-line @typescript-eslint/unbound-method
const objectToString = Object.prototype.toString;

/**
 * Checks whether given value's type is one of a few Error or Error-like
 * {@link isError}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isError(wat) {
  switch (objectToString.call(wat)) {
    case '[object Error]':
    case '[object Exception]':
    case '[object DOMException]':
    case '[object WebAssembly.Exception]':
      return true;
    default:
      return isInstanceOf(wat, Error);
  }
}
/**
 * Checks whether given value is an instance of the given built-in class.
 *
 * @param wat The value to be checked
 * @param className
 * @returns A boolean representing the result.
 */
function isBuiltin(wat, className) {
  return objectToString.call(wat) === `[object ${className}]`;
}

/**
 * Checks whether given value's type is ErrorEvent
 * {@link isErrorEvent}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isErrorEvent(wat) {
  return isBuiltin(wat, 'ErrorEvent');
}

/**
 * Checks whether given value's type is DOMError
 * {@link isDOMError}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isDOMError(wat) {
  return isBuiltin(wat, 'DOMError');
}

/**
 * Checks whether given value's type is DOMException
 * {@link isDOMException}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isDOMException(wat) {
  return isBuiltin(wat, 'DOMException');
}

/**
 * Checks whether given value's type is a string
 * {@link isString}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isString(wat) {
  return isBuiltin(wat, 'String');
}

/**
 * Checks whether given string is parameterized
 * {@link isParameterizedString}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isParameterizedString(wat) {
  return (
    typeof wat === 'object' &&
    wat !== null &&
    '__sentry_template_string__' in wat &&
    '__sentry_template_values__' in wat
  );
}

/**
 * Checks whether given value is a primitive (undefined, null, number, boolean, string, bigint, symbol)
 * {@link isPrimitive}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function is_isPrimitive(wat) {
  return wat === null || isParameterizedString(wat) || (typeof wat !== 'object' && typeof wat !== 'function');
}

/**
 * Checks whether given value's type is an object literal, or a class instance.
 * {@link isPlainObject}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isPlainObject(wat) {
  return isBuiltin(wat, 'Object');
}

/**
 * Checks whether given value's type is an Event instance
 * {@link isEvent}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isEvent(wat) {
  return typeof Event !== 'undefined' && isInstanceOf(wat, Event);
}

/**
 * Checks whether given value's type is an Element instance
 * {@link isElement}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isElement(wat) {
  return typeof Element !== 'undefined' && isInstanceOf(wat, Element);
}

/**
 * Checks whether given value's type is an regexp
 * {@link isRegExp}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isRegExp(wat) {
  return isBuiltin(wat, 'RegExp');
}

/**
 * Checks whether given value has a then function.
 * @param wat A value to be checked.
 */
function is_isThenable(wat) {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  return Boolean(wat && wat.then && typeof wat.then === 'function');
}

/**
 * Checks whether given value's type is a SyntheticEvent
 * {@link isSyntheticEvent}.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isSyntheticEvent(wat) {
  return isPlainObject(wat) && 'nativeEvent' in wat && 'preventDefault' in wat && 'stopPropagation' in wat;
}

/**
 * Checks whether given value's type is an instance of provided constructor.
 * {@link isInstanceOf}.
 *
 * @param wat A value to be checked.
 * @param base A constructor to be used in a check.
 * @returns A boolean representing the result.
 */
function isInstanceOf(wat, base) {
  try {
    return wat instanceof base;
  } catch (_e) {
    return false;
  }
}

/**
 * Checks whether given value's type is a Vue ViewModel.
 *
 * @param wat A value to be checked.
 * @returns A boolean representing the result.
 */
function isVueViewModel(wat) {
  // Not using Object.prototype.toString because in Vue 3 it would read the instance's Symbol(Symbol.toStringTag) property.
  return !!(typeof wat === 'object' && wat !== null && ((wat ).__isVue || (wat )._isVue));
}


//# sourceMappingURL=is.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/browser.js



const browser_WINDOW = worldwide_GLOBAL_OBJ ;

const DEFAULT_MAX_STRING_LENGTH = 80;

/**
 * Given a child DOM element, returns a query-selector statement describing that
 * and its ancestors
 * e.g. [HTMLElement] => body > div > input#foo.btn[name=baz]
 * @returns generated DOM path
 */
function htmlTreeAsString(
  elem,
  options = {},
) {
  if (!elem) {
    return '<unknown>';
  }

  // try/catch both:
  // - accessing event.target (see getsentry/raven-js#838, #768)
  // - `htmlTreeAsString` because it's complex, and just accessing the DOM incorrectly
  // - can throw an exception in some circumstances.
  try {
    let currentElem = elem ;
    const MAX_TRAVERSE_HEIGHT = 5;
    const out = [];
    let height = 0;
    let len = 0;
    const separator = ' > ';
    const sepLength = separator.length;
    let nextStr;
    const keyAttrs = Array.isArray(options) ? options : options.keyAttrs;
    const maxStringLength = (!Array.isArray(options) && options.maxStringLength) || DEFAULT_MAX_STRING_LENGTH;

    while (currentElem && height++ < MAX_TRAVERSE_HEIGHT) {
      nextStr = _htmlElementAsString(currentElem, keyAttrs);
      // bail out if
      // - nextStr is the 'html' element
      // - the length of the string that would be created exceeds maxStringLength
      //   (ignore this limit if we are on the first iteration)
      if (nextStr === 'html' || (height > 1 && len + out.length * sepLength + nextStr.length >= maxStringLength)) {
        break;
      }

      out.push(nextStr);

      len += nextStr.length;
      currentElem = currentElem.parentNode;
    }

    return out.reverse().join(separator);
  } catch (_oO) {
    return '<unknown>';
  }
}

/**
 * Returns a simple, query-selector representation of a DOM element
 * e.g. [HTMLElement] => input#foo.btn[name=baz]
 * @returns generated DOM path
 */
function _htmlElementAsString(el, keyAttrs) {
  const elem = el

;

  const out = [];

  if (!elem || !elem.tagName) {
    return '';
  }

  // @ts-expect-error WINDOW has HTMLElement
  if (browser_WINDOW.HTMLElement) {
    // If using the component name annotation plugin, this value may be available on the DOM node
    if (elem instanceof HTMLElement && elem.dataset) {
      if (elem.dataset['sentryComponent']) {
        return elem.dataset['sentryComponent'];
      }
      if (elem.dataset['sentryElement']) {
        return elem.dataset['sentryElement'];
      }
    }
  }

  out.push(elem.tagName.toLowerCase());

  // Pairs of attribute keys defined in `serializeAttribute` and their values on element.
  const keyAttrPairs =
    keyAttrs && keyAttrs.length
      ? keyAttrs.filter(keyAttr => elem.getAttribute(keyAttr)).map(keyAttr => [keyAttr, elem.getAttribute(keyAttr)])
      : null;

  if (keyAttrPairs && keyAttrPairs.length) {
    keyAttrPairs.forEach(keyAttrPair => {
      out.push(`[${keyAttrPair[0]}="${keyAttrPair[1]}"]`);
    });
  } else {
    if (elem.id) {
      out.push(`#${elem.id}`);
    }

    const className = elem.className;
    if (className && isString(className)) {
      const classes = className.split(/\s+/);
      for (const c of classes) {
        out.push(`.${c}`);
      }
    }
  }
  const allowedAttrs = ['aria-label', 'type', 'name', 'title', 'alt'];
  for (const k of allowedAttrs) {
    const attr = elem.getAttribute(k);
    if (attr) {
      out.push(`[${k}="${attr}"]`);
    }
  }

  return out.join('');
}

/**
 * A safe form of location.href
 */
function getLocationHref() {
  try {
    return browser_WINDOW.document.location.href;
  } catch (oO) {
    return '';
  }
}

/**
 * Gets a DOM element by using document.querySelector.
 *
 * This wrapper will first check for the existence of the function before
 * actually calling it so that we don't have to take care of this check,
 * every time we want to access the DOM.
 *
 * Reason: DOM/querySelector is not available in all environments.
 *
 * We have to cast to any because utils can be consumed by a variety of environments,
 * and we don't want to break TS users. If you know what element will be selected by
 * `document.querySelector`, specify it as part of the generic call. For example,
 * `const element = getDomElement<Element>('selector');`
 *
 * @param selector the selector string passed on to document.querySelector
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getDomElement(selector) {
  if (browser_WINDOW.document && browser_WINDOW.document.querySelector) {
    return browser_WINDOW.document.querySelector(selector) ;
  }
  return null;
}

/**
 * Given a DOM element, traverses up the tree until it finds the first ancestor node
 * that has the `data-sentry-component` or `data-sentry-element` attribute with `data-sentry-component` taking
 * precedence. This attribute is added at build-time by projects that have the component name annotation plugin installed.
 *
 * @returns a string representation of the component for the provided DOM element, or `null` if not found
 */
function getComponentName(elem) {
  // @ts-expect-error WINDOW has HTMLElement
  if (!browser_WINDOW.HTMLElement) {
    return null;
  }

  let currentElem = elem ;
  const MAX_TRAVERSE_HEIGHT = 5;
  for (let i = 0; i < MAX_TRAVERSE_HEIGHT; i++) {
    if (!currentElem) {
      return null;
    }

    if (currentElem instanceof HTMLElement) {
      if (currentElem.dataset['sentryComponent']) {
        return currentElem.dataset['sentryComponent'];
      }
      if (currentElem.dataset['sentryElement']) {
        return currentElem.dataset['sentryElement'];
      }
    }

    currentElem = currentElem.parentNode;
  }

  return null;
}


//# sourceMappingURL=browser.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/string.js


/**
 * Truncates given string to the maximum characters count
 *
 * @param str An object that contains serializable values
 * @param max Maximum number of characters in truncated string (0 = unlimited)
 * @returns string Encoded
 */
function truncate(str, max = 0) {
  if (typeof str !== 'string' || max === 0) {
    return str;
  }
  return str.length <= max ? str : `${str.slice(0, max)}...`;
}

/**
 * This is basically just `trim_line` from
 * https://github.com/getsentry/sentry/blob/master/src/sentry/lang/javascript/processor.py#L67
 *
 * @param str An object that contains serializable values
 * @param max Maximum number of characters in truncated string
 * @returns string Encoded
 */
function string_snipLine(line, colno) {
  let newLine = line;
  const lineLength = newLine.length;
  if (lineLength <= 150) {
    return newLine;
  }
  if (colno > lineLength) {
    // eslint-disable-next-line no-param-reassign
    colno = lineLength;
  }

  let start = Math.max(colno - 60, 0);
  if (start < 5) {
    start = 0;
  }

  let end = Math.min(start + 140, lineLength);
  if (end > lineLength - 5) {
    end = lineLength;
  }
  if (end === lineLength) {
    start = Math.max(end - 140, 0);
  }

  newLine = newLine.slice(start, end);
  if (start > 0) {
    newLine = `'{snip} ${newLine}`;
  }
  if (end < lineLength) {
    newLine += ' {snip}';
  }

  return newLine;
}

/**
 * Join values in array
 * @param input array of values to be joined together
 * @param delimiter string to be placed in-between values
 * @returns Joined values
 */
function safeJoin(input, delimiter) {
  if (!Array.isArray(input)) {
    return '';
  }

  const output = [];
  // eslint-disable-next-line @typescript-eslint/prefer-for-of
  for (let i = 0; i < input.length; i++) {
    const value = input[i];
    try {
      // This is a hack to fix a Vue3-specific bug that causes an infinite loop of
      // console warnings. This happens when a Vue template is rendered with
      // an undeclared variable, which we try to stringify, ultimately causing
      // Vue to issue another warning which repeats indefinitely.
      // see: https://github.com/getsentry/sentry-javascript/pull/8981
      if (isVueViewModel(value)) {
        output.push('[VueViewModel]');
      } else {
        output.push(String(value));
      }
    } catch (e) {
      output.push('[value cannot be serialized]');
    }
  }

  return output.join(delimiter);
}

/**
 * Checks if the given value matches a regex or string
 *
 * @param value The string to test
 * @param pattern Either a regex or a string against which `value` will be matched
 * @param requireExactStringMatch If true, `value` must match `pattern` exactly. If false, `value` will match
 * `pattern` if it contains `pattern`. Only applies to string-type patterns.
 */
function isMatchingPattern(
  value,
  pattern,
  requireExactStringMatch = false,
) {
  if (!isString(value)) {
    return false;
  }

  if (isRegExp(pattern)) {
    return pattern.test(value);
  }
  if (isString(pattern)) {
    return requireExactStringMatch ? value === pattern : value.includes(pattern);
  }

  return false;
}

/**
 * Test the given string against an array of strings and regexes. By default, string matching is done on a
 * substring-inclusion basis rather than a strict equality basis
 *
 * @param testString The string to test
 * @param patterns The patterns against which to test the string
 * @param requireExactStringMatch If true, `testString` must match one of the given string patterns exactly in order to
 * count. If false, `testString` will match a string pattern if it contains that pattern.
 * @returns
 */
function stringMatchesSomePattern(
  testString,
  patterns = [],
  requireExactStringMatch = false,
) {
  return patterns.some(pattern => isMatchingPattern(testString, pattern, requireExactStringMatch));
}


//# sourceMappingURL=string.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/object.js






/**
 * Replace a method in an object with a wrapped version of itself.
 *
 * @param source An object that contains a method to be wrapped.
 * @param name The name of the method to be wrapped.
 * @param replacementFactory A higher-order function that takes the original version of the given method and returns a
 * wrapped version. Note: The function returned by `replacementFactory` needs to be a non-arrow function, in order to
 * preserve the correct value of `this`, and the original method must be called using `origMethod.call(this, <other
 * args>)` or `origMethod.apply(this, [<other args>])` (rather than being called directly), again to preserve `this`.
 * @returns void
 */
function fill(source, name, replacementFactory) {
  if (!(name in source)) {
    return;
  }

  const original = source[name] ;
  const wrapped = replacementFactory(original) ;

  // Make sure it's a function first, as we need to attach an empty prototype for `defineProperties` to work
  // otherwise it'll throw "TypeError: Object.defineProperties called on non-object"
  if (typeof wrapped === 'function') {
    markFunctionWrapped(wrapped, original);
  }

  try {
    source[name] = wrapped;
  } catch (e) {
    utils_hoist_debug_build_DEBUG_BUILD && logger_logger.log(`Failed to replace method "${name}" in object`, source);
  }
}

/**
 * Defines a non-enumerable property on the given object.
 *
 * @param obj The object on which to set the property
 * @param name The name of the property to be set
 * @param value The value to which to set the property
 */
function object_addNonEnumerableProperty(obj, name, value) {
  try {
    Object.defineProperty(obj, name, {
      // enumerable: false, // the default, so we can save on bundle size by not explicitly setting it
      value: value,
      writable: true,
      configurable: true,
    });
  } catch (o_O) {
    utils_hoist_debug_build_DEBUG_BUILD && logger_logger.log(`Failed to add non-enumerable property "${name}" to object`, obj);
  }
}

/**
 * Remembers the original function on the wrapped function and
 * patches up the prototype.
 *
 * @param wrapped the wrapper function
 * @param original the original function that gets wrapped
 */
function markFunctionWrapped(wrapped, original) {
  try {
    const proto = original.prototype || {};
    wrapped.prototype = original.prototype = proto;
    object_addNonEnumerableProperty(wrapped, '__sentry_original__', original);
  } catch (o_O) {} // eslint-disable-line no-empty
}

/**
 * This extracts the original function if available.  See
 * `markFunctionWrapped` for more information.
 *
 * @param func the function to unwrap
 * @returns the unwrapped version of the function if available.
 */
// eslint-disable-next-line @typescript-eslint/ban-types
function getOriginalFunction(func) {
  return func.__sentry_original__;
}

/**
 * Encodes given object into url-friendly format
 *
 * @param object An object that contains serializable values
 * @returns string Encoded
 *
 * @deprecated This function is deprecated and will be removed in the next major version of the SDK.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function urlEncode(object) {
  return Object.entries(object)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

/**
 * Transforms any `Error` or `Event` into a plain object with all of their enumerable properties, and some of their
 * non-enumerable properties attached.
 *
 * @param value Initial source that we have to transform in order for it to be usable by the serializer
 * @returns An Event or Error turned into an object - or the value argument itself, when value is neither an Event nor
 *  an Error.
 */
function convertToPlainObject(value)

 {
  if (isError(value)) {
    return {
      message: value.message,
      name: value.name,
      stack: value.stack,
      ...getOwnProperties(value),
    };
  } else if (isEvent(value)) {
    const newObj

 = {
      type: value.type,
      target: serializeEventTarget(value.target),
      currentTarget: serializeEventTarget(value.currentTarget),
      ...getOwnProperties(value),
    };

    if (typeof CustomEvent !== 'undefined' && isInstanceOf(value, CustomEvent)) {
      newObj.detail = value.detail;
    }

    return newObj;
  } else {
    return value;
  }
}

/** Creates a string representation of the target of an `Event` object */
function serializeEventTarget(target) {
  try {
    return isElement(target) ? htmlTreeAsString(target) : Object.prototype.toString.call(target);
  } catch (_oO) {
    return '<unknown>';
  }
}

/** Filters out all but an object's own properties */
function getOwnProperties(obj) {
  if (typeof obj === 'object' && obj !== null) {
    const extractedProps = {};
    for (const property in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, property)) {
        extractedProps[property] = (obj )[property];
      }
    }
    return extractedProps;
  } else {
    return {};
  }
}

/**
 * Given any captured exception, extract its keys and create a sorted
 * and truncated list that will be used inside the event message.
 * eg. `Non-error exception captured with keys: foo, bar, baz`
 */
function extractExceptionKeysForMessage(exception, maxLength = 40) {
  const keys = Object.keys(convertToPlainObject(exception));
  keys.sort();

  const firstKey = keys[0];

  if (!firstKey) {
    return '[object has no keys]';
  }

  if (firstKey.length >= maxLength) {
    return truncate(firstKey, maxLength);
  }

  for (let includedKeys = keys.length; includedKeys > 0; includedKeys--) {
    const serialized = keys.slice(0, includedKeys).join(', ');
    if (serialized.length > maxLength) {
      continue;
    }
    if (includedKeys === keys.length) {
      return serialized;
    }
    return truncate(serialized, maxLength);
  }

  return '';
}

/**
 * Given any object, return a new object having removed all fields whose value was `undefined`.
 * Works recursively on objects and arrays.
 *
 * Attention: This function keeps circular references in the returned object.
 */
function object_dropUndefinedKeys(inputValue) {
  // This map keeps track of what already visited nodes map to.
  // Our Set - based memoBuilder doesn't work here because we want to the output object to have the same circular
  // references as the input object.
  const memoizationMap = new Map();

  // This function just proxies `_dropUndefinedKeys` to keep the `memoBuilder` out of this function's API
  return _dropUndefinedKeys(inputValue, memoizationMap);
}

function _dropUndefinedKeys(inputValue, memoizationMap) {
  if (isPojo(inputValue)) {
    // If this node has already been visited due to a circular reference, return the object it was mapped to in the new object
    const memoVal = memoizationMap.get(inputValue);
    if (memoVal !== undefined) {
      return memoVal ;
    }

    const returnValue = {};
    // Store the mapping of this value in case we visit it again, in case of circular data
    memoizationMap.set(inputValue, returnValue);

    for (const key of Object.getOwnPropertyNames(inputValue)) {
      if (typeof inputValue[key] !== 'undefined') {
        returnValue[key] = _dropUndefinedKeys(inputValue[key], memoizationMap);
      }
    }

    return returnValue ;
  }

  if (Array.isArray(inputValue)) {
    // If this node has already been visited due to a circular reference, return the array it was mapped to in the new object
    const memoVal = memoizationMap.get(inputValue);
    if (memoVal !== undefined) {
      return memoVal ;
    }

    const returnValue = [];
    // Store the mapping of this value in case we visit it again, in case of circular data
    memoizationMap.set(inputValue, returnValue);

    inputValue.forEach((item) => {
      returnValue.push(_dropUndefinedKeys(item, memoizationMap));
    });

    return returnValue ;
  }

  return inputValue;
}

function isPojo(input) {
  if (!isPlainObject(input)) {
    return false;
  }

  try {
    const name = (Object.getPrototypeOf(input) ).constructor.name;
    return !name || name === 'Object';
  } catch (e2) {
    return true;
  }
}

/**
 * Ensure that something is an object.
 *
 * Turns `undefined` and `null` into `String`s and all other primitives into instances of their respective wrapper
 * classes (String, Boolean, Number, etc.). Acts as the identity function on non-primitives.
 *
 * @param wat The subject of the objectification
 * @returns A version of `wat` which can safely be used with `Object` class methods
 */
function objectify(wat) {
  let objectified;
  switch (true) {
    // this will catch both undefined and null
    case wat == undefined:
      objectified = new String(wat);
      break;

    // Though symbols and bigints do have wrapper classes (`Symbol` and `BigInt`, respectively), for whatever reason
    // those classes don't have constructors which can be used with the `new` keyword. We therefore need to cast each as
    // an object in order to wrap it.
    case typeof wat === 'symbol' || typeof wat === 'bigint':
      objectified = Object(wat);
      break;

    // this will catch the remaining primitives: `String`, `Number`, and `Boolean`
    case isPrimitive(wat):
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      objectified = new (wat ).constructor(wat);
      break;

    // by process of elimination, at this point we know that `wat` must already be an object
    default:
      objectified = wat;
      break;
  }
  return objectified;
}


//# sourceMappingURL=object.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/misc.js




/**
 * UUID4 generator
 *
 * @returns string Generated UUID4.
 */
function misc_uuid4() {
  const gbl = worldwide_GLOBAL_OBJ ;
  const crypto = gbl.crypto || gbl.msCrypto;

  let getRandomByte = () => Math.random() * 16;
  try {
    if (crypto && crypto.randomUUID) {
      return crypto.randomUUID().replace(/-/g, '');
    }
    if (crypto && crypto.getRandomValues) {
      getRandomByte = () => {
        // crypto.getRandomValues might return undefined instead of the typed array
        // in old Chromium versions (e.g. 23.0.1235.0 (151422))
        // However, `typedArray` is still filled in-place.
        // @see https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#typedarray
        const typedArray = new Uint8Array(1);
        crypto.getRandomValues(typedArray);
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        return typedArray[0];
      };
    }
  } catch (_) {
    // some runtimes can crash invoking crypto
    // https://github.com/getsentry/sentry-javascript/issues/8935
  }

  // http://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript/2117523#2117523
  // Concatenating the following numbers as strings results in '10000000100040008000100000000000'
  return (([1e7] ) + 1e3 + 4e3 + 8e3 + 1e11).replace(/[018]/g, c =>
    // eslint-disable-next-line no-bitwise
    ((c ) ^ ((getRandomByte() & 15) >> ((c ) / 4))).toString(16),
  );
}

function getFirstException(event) {
  return event.exception && event.exception.values ? event.exception.values[0] : undefined;
}

/**
 * Extracts either message or type+value from an event that can be used for user-facing logs
 * @returns event's description
 */
function getEventDescription(event) {
  const { message, event_id: eventId } = event;
  if (message) {
    return message;
  }

  const firstException = getFirstException(event);
  if (firstException) {
    if (firstException.type && firstException.value) {
      return `${firstException.type}: ${firstException.value}`;
    }
    return firstException.type || firstException.value || eventId || '<unknown>';
  }
  return eventId || '<unknown>';
}

/**
 * Adds exception values, type and value to an synthetic Exception.
 * @param event The event to modify.
 * @param value Value of the exception.
 * @param type Type of the exception.
 * @hidden
 */
function addExceptionTypeValue(event, value, type) {
  const exception = (event.exception = event.exception || {});
  const values = (exception.values = exception.values || []);
  const firstException = (values[0] = values[0] || {});
  if (!firstException.value) {
    firstException.value = value || '';
  }
  if (!firstException.type) {
    firstException.type = type || 'Error';
  }
}

/**
 * Adds exception mechanism data to a given event. Uses defaults if the second parameter is not passed.
 *
 * @param event The event to modify.
 * @param newMechanism Mechanism data to add to the event.
 * @hidden
 */
function addExceptionMechanism(event, newMechanism) {
  const firstException = getFirstException(event);
  if (!firstException) {
    return;
  }

  const defaultMechanism = { type: 'generic', handled: true };
  const currentMechanism = firstException.mechanism;
  firstException.mechanism = { ...defaultMechanism, ...currentMechanism, ...newMechanism };

  if (newMechanism && 'data' in newMechanism) {
    const mergedData = { ...(currentMechanism && currentMechanism.data), ...newMechanism.data };
    firstException.mechanism.data = mergedData;
  }
}

// https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
const SEMVER_REGEXP =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/**
 * Represents Semantic Versioning object
 */

function _parseInt(input) {
  return parseInt(input || '', 10);
}

/**
 * Parses input into a SemVer interface
 * @param input string representation of a semver version
 */
function parseSemver(input) {
  const match = input.match(SEMVER_REGEXP) || [];
  const major = _parseInt(match[1]);
  const minor = _parseInt(match[2]);
  const patch = _parseInt(match[3]);
  return {
    buildmetadata: match[5],
    major: isNaN(major) ? undefined : major,
    minor: isNaN(minor) ? undefined : minor,
    patch: isNaN(patch) ? undefined : patch,
    prerelease: match[4],
  };
}

/**
 * This function adds context (pre/post/line) lines to the provided frame
 *
 * @param lines string[] containing all lines
 * @param frame StackFrame that will be mutated
 * @param linesOfContext number of context lines we want to add pre/post
 */
function addContextToFrame(lines, frame, linesOfContext = 5) {
  // When there is no line number in the frame, attaching context is nonsensical and will even break grouping
  if (frame.lineno === undefined) {
    return;
  }

  const maxLines = lines.length;
  const sourceLine = Math.max(Math.min(maxLines - 1, frame.lineno - 1), 0);

  frame.pre_context = lines
    .slice(Math.max(0, sourceLine - linesOfContext), sourceLine)
    .map((line) => snipLine(line, 0));

  // We guard here to ensure this is not larger than the existing number of lines
  const lineIndex = Math.min(maxLines - 1, sourceLine);

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  frame.context_line = snipLine(lines[lineIndex], frame.colno || 0);

  frame.post_context = lines
    .slice(Math.min(sourceLine + 1, maxLines), sourceLine + 1 + linesOfContext)
    .map((line) => snipLine(line, 0));
}

/**
 * Checks whether or not we've already captured the given exception (note: not an identical exception - the very object
 * in question), and marks it captured if not.
 *
 * This is useful because it's possible for an error to get captured by more than one mechanism. After we intercept and
 * record an error, we rethrow it (assuming we've intercepted it before it's reached the top-level global handlers), so
 * that we don't interfere with whatever effects the error might have had were the SDK not there. At that point, because
 * the error has been rethrown, it's possible for it to bubble up to some other code we've instrumented. If it's not
 * caught after that, it will bubble all the way up to the global handlers (which of course we also instrument). This
 * function helps us ensure that even if we encounter the same error more than once, we only record it the first time we
 * see it.
 *
 * Note: It will ignore primitives (always return `false` and not mark them as seen), as properties can't be set on
 * them. {@link: Object.objectify} can be used on exceptions to convert any that are primitives into their equivalent
 * object wrapper forms so that this check will always work. However, because we need to flag the exact object which
 * will get rethrown, and because that rethrowing happens outside of the event processing pipeline, the objectification
 * must be done before the exception captured.
 *
 * @param A thrown exception to check or flag as having been seen
 * @returns `true` if the exception has already been captured, `false` if not (with the side effect of marking it seen)
 */
function checkOrSetAlreadyCaught(exception) {
  if (isAlreadyCaptured(exception)) {
    return true;
  }

  try {
    // set it this way rather than by assignment so that it's not ennumerable and therefore isn't recorded by the
    // `ExtraErrorData` integration
    object_addNonEnumerableProperty(exception , '__sentry_captured__', true);
  } catch (err) {
    // `exception` is a primitive, so we can't mark it seen
  }

  return false;
}

function isAlreadyCaptured(exception) {
  try {
    return (exception ).__sentry_captured__;
  } catch (e) {} // eslint-disable-line no-empty
}

/**
 * Checks whether the given input is already an array, and if it isn't, wraps it in one.
 *
 * @param maybeArray Input to turn into an array, if necessary
 * @returns The input, if already an array, or an array with the input as the only element, if not
 *
 * @deprecated This function has been deprecated and will not be replaced.
 */
function arrayify(maybeArray) {
  return Array.isArray(maybeArray) ? maybeArray : [maybeArray];
}


//# sourceMappingURL=misc.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/integrations/inboundfilters.js






// "Script error." is hard coded into browsers for errors that it can't read.
// this is the result of a script being pulled in from an external domain and CORS.
const DEFAULT_IGNORE_ERRORS = [
  /^Script error\.?$/,
  /^Javascript error: Script error\.? on line 0$/,
  /^ResizeObserver loop completed with undelivered notifications.$/, // The browser logs this when a ResizeObserver handler takes a bit longer. Usually this is not an actual issue though. It indicates slowness.
  /^Cannot redefine property: googletag$/, // This is thrown when google tag manager is used in combination with an ad blocker
  "undefined is not an object (evaluating 'a.L')", // Random error that happens but not actionable or noticeable to end-users.
  'can\'t redefine non-configurable property "solana"', // Probably a browser extension or custom browser (Brave) throwing this error
  "vv().getRestrictions is not a function. (In 'vv().getRestrictions(1,a)', 'vv().getRestrictions' is undefined)", // Error thrown by GTM, seemingly not affecting end-users
  "Can't find variable: _AutofillCallbackHandler", // Unactionable error in instagram webview https://developers.facebook.com/community/threads/320013549791141/
  /^Non-Error promise rejection captured with value: Object Not Found Matching Id:\d+, MethodName:simulateEvent, ParamCount:\d+$/, // unactionable error from CEFSharp, a .NET library that embeds chromium in .NET apps
];

/** Options for the InboundFilters integration */

const INTEGRATION_NAME = 'InboundFilters';
const _inboundFiltersIntegration = ((options = {}) => {
  return {
    name: INTEGRATION_NAME,
    processEvent(event, _hint, client) {
      const clientOptions = client.getOptions();
      const mergedOptions = _mergeOptions(options, clientOptions);
      return _shouldDropEvent(event, mergedOptions) ? null : event;
    },
  };
}) ;

const inboundFiltersIntegration = defineIntegration(_inboundFiltersIntegration);

function _mergeOptions(
  internalOptions = {},
  clientOptions = {},
) {
  return {
    allowUrls: [...(internalOptions.allowUrls || []), ...(clientOptions.allowUrls || [])],
    denyUrls: [...(internalOptions.denyUrls || []), ...(clientOptions.denyUrls || [])],
    ignoreErrors: [
      ...(internalOptions.ignoreErrors || []),
      ...(clientOptions.ignoreErrors || []),
      ...(internalOptions.disableErrorDefaults ? [] : DEFAULT_IGNORE_ERRORS),
    ],
    ignoreTransactions: [...(internalOptions.ignoreTransactions || []), ...(clientOptions.ignoreTransactions || [])],
    ignoreInternal: internalOptions.ignoreInternal !== undefined ? internalOptions.ignoreInternal : true,
  };
}

function _shouldDropEvent(event, options) {
  if (options.ignoreInternal && _isSentryError(event)) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(`Event dropped due to being internal Sentry Error.\nEvent: ${getEventDescription(event)}`);
    return true;
  }
  if (_isIgnoredError(event, options.ignoreErrors)) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(
        `Event dropped due to being matched by \`ignoreErrors\` option.\nEvent: ${getEventDescription(event)}`,
      );
    return true;
  }
  if (_isUselessError(event)) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(
        `Event dropped due to not having an error message, error type or stacktrace.\nEvent: ${getEventDescription(
          event,
        )}`,
      );
    return true;
  }
  if (_isIgnoredTransaction(event, options.ignoreTransactions)) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(
        `Event dropped due to being matched by \`ignoreTransactions\` option.\nEvent: ${getEventDescription(event)}`,
      );
    return true;
  }
  if (_isDeniedUrl(event, options.denyUrls)) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(
        `Event dropped due to being matched by \`denyUrls\` option.\nEvent: ${getEventDescription(
          event,
        )}.\nUrl: ${_getEventFilterUrl(event)}`,
      );
    return true;
  }
  if (!_isAllowedUrl(event, options.allowUrls)) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(
        `Event dropped due to not being matched by \`allowUrls\` option.\nEvent: ${getEventDescription(
          event,
        )}.\nUrl: ${_getEventFilterUrl(event)}`,
      );
    return true;
  }
  return false;
}

function _isIgnoredError(event, ignoreErrors) {
  // If event.type, this is not an error
  if (event.type || !ignoreErrors || !ignoreErrors.length) {
    return false;
  }

  return _getPossibleEventMessages(event).some(message => stringMatchesSomePattern(message, ignoreErrors));
}

function _isIgnoredTransaction(event, ignoreTransactions) {
  if (event.type !== 'transaction' || !ignoreTransactions || !ignoreTransactions.length) {
    return false;
  }

  const name = event.transaction;
  return name ? stringMatchesSomePattern(name, ignoreTransactions) : false;
}

function _isDeniedUrl(event, denyUrls) {
  // TODO: Use Glob instead?
  if (!denyUrls || !denyUrls.length) {
    return false;
  }
  const url = _getEventFilterUrl(event);
  return !url ? false : stringMatchesSomePattern(url, denyUrls);
}

function _isAllowedUrl(event, allowUrls) {
  // TODO: Use Glob instead?
  if (!allowUrls || !allowUrls.length) {
    return true;
  }
  const url = _getEventFilterUrl(event);
  return !url ? true : stringMatchesSomePattern(url, allowUrls);
}

function _getPossibleEventMessages(event) {
  const possibleMessages = [];

  if (event.message) {
    possibleMessages.push(event.message);
  }

  let lastException;
  try {
    // @ts-expect-error Try catching to save bundle size
    lastException = event.exception.values[event.exception.values.length - 1];
  } catch (e) {
    // try catching to save bundle size checking existence of variables
  }

  if (lastException) {
    if (lastException.value) {
      possibleMessages.push(lastException.value);
      if (lastException.type) {
        possibleMessages.push(`${lastException.type}: ${lastException.value}`);
      }
    }
  }

  return possibleMessages;
}

function _isSentryError(event) {
  try {
    // @ts-expect-error can't be a sentry error if undefined
    return event.exception.values[0].type === 'SentryError';
  } catch (e) {
    // ignore
  }
  return false;
}

function _getLastValidUrl(frames = []) {
  for (let i = frames.length - 1; i >= 0; i--) {
    const frame = frames[i];

    if (frame && frame.filename !== '<anonymous>' && frame.filename !== '[native code]') {
      return frame.filename || null;
    }
  }

  return null;
}

function _getEventFilterUrl(event) {
  try {
    let frames;
    try {
      // @ts-expect-error we only care about frames if the whole thing here is defined
      frames = event.exception.values[0].stacktrace.frames;
    } catch (e) {
      // ignore
    }
    return frames ? _getLastValidUrl(frames) : null;
  } catch (oO) {
    debug_build_DEBUG_BUILD && logger_logger.error(`Cannot extract url for event ${getEventDescription(event)}`);
    return null;
  }
}

function _isUselessError(event) {
  if (event.type) {
    // event is not an error
    return false;
  }

  // We only want to consider events for dropping that actually have recorded exception values.
  if (!event.exception || !event.exception.values || event.exception.values.length === 0) {
    return false;
  }

  return (
    // No top-level message
    !event.message &&
    // There are no exception values that have a stacktrace, a non-generic-Error type or value
    !event.exception.values.some(value => value.stacktrace || (value.type && value.type !== 'Error') || value.value)
  );
}


//# sourceMappingURL=inboundfilters.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/carrier.js



/**
 * An object that contains globally accessible properties and maintains a scope stack.
 * @hidden
 */

/**
 * Returns the global shim registry.
 *
 * FIXME: This function is problematic, because despite always returning a valid Carrier,
 * it has an optional `__SENTRY__` property, which then in turn requires us to always perform an unnecessary check
 * at the call-site. We always access the carrier through this function, so we can guarantee that `__SENTRY__` is there.
 **/
function carrier_getMainCarrier() {
  // This ensures a Sentry carrier exists
  carrier_getSentryCarrier(worldwide_GLOBAL_OBJ);
  return worldwide_GLOBAL_OBJ;
}

/** Will either get the existing sentry carrier, or create a new one. */
function carrier_getSentryCarrier(carrier) {
  const __SENTRY__ = (carrier.__SENTRY__ = carrier.__SENTRY__ || {});

  // For now: First SDK that sets the .version property wins
  __SENTRY__.version = __SENTRY__.version || SDK_VERSION;

  // Intentionally populating and returning the version of "this" SDK instance
  // rather than what's set in .version so that "this" SDK always gets its carrier
  return (__SENTRY__[SDK_VERSION] = __SENTRY__[SDK_VERSION] || {});
}


//# sourceMappingURL=carrier.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/time.js


const ONE_SECOND_IN_MS = 1000;

/**
 * A partial definition of the [Performance Web API]{@link https://developer.mozilla.org/en-US/docs/Web/API/Performance}
 * for accessing a high-resolution monotonic clock.
 */

/**
 * Returns a timestamp in seconds since the UNIX epoch using the Date API.
 *
 * TODO(v8): Return type should be rounded.
 */
function dateTimestampInSeconds() {
  return Date.now() / ONE_SECOND_IN_MS;
}

/**
 * Returns a wrapper around the native Performance API browser implementation, or undefined for browsers that do not
 * support the API.
 *
 * Wrapping the native API works around differences in behavior from different browsers.
 */
function createUnixTimestampInSecondsFunc() {
  const { performance } = worldwide_GLOBAL_OBJ ;
  if (!performance || !performance.now) {
    return dateTimestampInSeconds;
  }

  // Some browser and environments don't have a timeOrigin, so we fallback to
  // using Date.now() to compute the starting time.
  const approxStartingTimeOrigin = Date.now() - performance.now();
  const timeOrigin = performance.timeOrigin == undefined ? approxStartingTimeOrigin : performance.timeOrigin;

  // performance.now() is a monotonic clock, which means it starts at 0 when the process begins. To get the current
  // wall clock time (actual UNIX timestamp), we need to add the starting time origin and the current time elapsed.
  //
  // TODO: This does not account for the case where the monotonic clock that powers performance.now() drifts from the
  // wall clock time, which causes the returned timestamp to be inaccurate. We should investigate how to detect and
  // correct for this.
  // See: https://github.com/getsentry/sentry-javascript/issues/2590
  // See: https://github.com/mdn/content/issues/4713
  // See: https://dev.to/noamr/when-a-millisecond-is-not-a-millisecond-3h6
  return () => {
    return (timeOrigin + performance.now()) / ONE_SECOND_IN_MS;
  };
}

/**
 * Returns a timestamp in seconds since the UNIX epoch using either the Performance or Date APIs, depending on the
 * availability of the Performance API.
 *
 * BUG: Note that because of how browsers implement the Performance API, the clock might stop when the computer is
 * asleep. This creates a skew between `dateTimestampInSeconds` and `timestampInSeconds`. The
 * skew can grow to arbitrary amounts like days, weeks or months.
 * See https://github.com/getsentry/sentry-javascript/issues/2590.
 */
const time_timestampInSeconds = createUnixTimestampInSecondsFunc();

/**
 * Internal helper to store what is the source of browserPerformanceTimeOrigin below. For debugging only.
 *
 * @deprecated This variable will be removed in the next major version.
 */
let _browserPerformanceTimeOriginMode;

/**
 * The number of milliseconds since the UNIX epoch. This value is only usable in a browser, and only when the
 * performance API is available.
 */
const browserPerformanceTimeOrigin = (() => {
  // Unfortunately browsers may report an inaccurate time origin data, through either performance.timeOrigin or
  // performance.timing.navigationStart, which results in poor results in performance data. We only treat time origin
  // data as reliable if they are within a reasonable threshold of the current time.

  const { performance } = worldwide_GLOBAL_OBJ ;
  if (!performance || !performance.now) {
    // eslint-disable-next-line deprecation/deprecation
    _browserPerformanceTimeOriginMode = 'none';
    return undefined;
  }

  const threshold = 3600 * 1000;
  const performanceNow = performance.now();
  const dateNow = Date.now();

  // if timeOrigin isn't available set delta to threshold so it isn't used
  const timeOriginDelta = performance.timeOrigin
    ? Math.abs(performance.timeOrigin + performanceNow - dateNow)
    : threshold;
  const timeOriginIsReliable = timeOriginDelta < threshold;

  // While performance.timing.navigationStart is deprecated in favor of performance.timeOrigin, performance.timeOrigin
  // is not as widely supported. Namely, performance.timeOrigin is undefined in Safari as of writing.
  // Also as of writing, performance.timing is not available in Web Workers in mainstream browsers, so it is not always
  // a valid fallback. In the absence of an initial time provided by the browser, fallback to the current time from the
  // Date API.
  // eslint-disable-next-line deprecation/deprecation
  const navigationStart = performance.timing && performance.timing.navigationStart;
  const hasNavigationStart = typeof navigationStart === 'number';
  // if navigationStart isn't available set delta to threshold so it isn't used
  const navigationStartDelta = hasNavigationStart ? Math.abs(navigationStart + performanceNow - dateNow) : threshold;
  const navigationStartIsReliable = navigationStartDelta < threshold;

  if (timeOriginIsReliable || navigationStartIsReliable) {
    // Use the more reliable time origin
    if (timeOriginDelta <= navigationStartDelta) {
      // eslint-disable-next-line deprecation/deprecation
      _browserPerformanceTimeOriginMode = 'timeOrigin';
      return performance.timeOrigin;
    } else {
      // eslint-disable-next-line deprecation/deprecation
      _browserPerformanceTimeOriginMode = 'navigationStart';
      return navigationStart;
    }
  }

  // Either both timeOrigin and navigationStart are skewed or neither is available, fallback to Date.
  // eslint-disable-next-line deprecation/deprecation
  _browserPerformanceTimeOriginMode = 'dateNow';
  return dateNow;
})();


//# sourceMappingURL=time.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/session.js








/**
 * Creates a new `Session` object by setting certain default parameters. If optional @param context
 * is passed, the passed properties are applied to the session object.
 *
 * @param context (optional) additional properties to be applied to the returned session object
 *
 * @returns a new `Session` object
 */
function makeSession(context) {
  // Both timestamp and started are in seconds since the UNIX epoch.
  const startingTime = time_timestampInSeconds();

  const session = {
    sid: misc_uuid4(),
    init: true,
    timestamp: startingTime,
    started: startingTime,
    duration: 0,
    status: 'ok',
    errors: 0,
    ignoreDuration: false,
    toJSON: () => sessionToJSON(session),
  };

  if (context) {
    updateSession(session, context);
  }

  return session;
}

/**
 * Updates a session object with the properties passed in the context.
 *
 * Note that this function mutates the passed object and returns void.
 * (Had to do this instead of returning a new and updated session because closing and sending a session
 * makes an update to the session after it was passed to the sending logic.
 * @see BaseClient.captureSession )
 *
 * @param session the `Session` to update
 * @param context the `SessionContext` holding the properties that should be updated in @param session
 */
// eslint-disable-next-line complexity
function updateSession(session, context = {}) {
  if (context.user) {
    if (!session.ipAddress && context.user.ip_address) {
      session.ipAddress = context.user.ip_address;
    }

    if (!session.did && !context.did) {
      session.did = context.user.id || context.user.email || context.user.username;
    }
  }

  session.timestamp = context.timestamp || time_timestampInSeconds();

  if (context.abnormal_mechanism) {
    session.abnormal_mechanism = context.abnormal_mechanism;
  }

  if (context.ignoreDuration) {
    session.ignoreDuration = context.ignoreDuration;
  }
  if (context.sid) {
    // Good enough uuid validation. — Kamil
    session.sid = context.sid.length === 32 ? context.sid : misc_uuid4();
  }
  if (context.init !== undefined) {
    session.init = context.init;
  }
  if (!session.did && context.did) {
    session.did = `${context.did}`;
  }
  if (typeof context.started === 'number') {
    session.started = context.started;
  }
  if (session.ignoreDuration) {
    session.duration = undefined;
  } else if (typeof context.duration === 'number') {
    session.duration = context.duration;
  } else {
    const duration = session.timestamp - session.started;
    session.duration = duration >= 0 ? duration : 0;
  }
  if (context.release) {
    session.release = context.release;
  }
  if (context.environment) {
    session.environment = context.environment;
  }
  if (!session.ipAddress && context.ipAddress) {
    session.ipAddress = context.ipAddress;
  }
  if (!session.userAgent && context.userAgent) {
    session.userAgent = context.userAgent;
  }
  if (typeof context.errors === 'number') {
    session.errors = context.errors;
  }
  if (context.status) {
    session.status = context.status;
  }
}

/**
 * Closes a session by setting its status and updating the session object with it.
 * Internally calls `updateSession` to update the passed session object.
 *
 * Note that this function mutates the passed session (@see updateSession for explanation).
 *
 * @param session the `Session` object to be closed
 * @param status the `SessionStatus` with which the session was closed. If you don't pass a status,
 *               this function will keep the previously set status, unless it was `'ok'` in which case
 *               it is changed to `'exited'`.
 */
function closeSession(session, status) {
  let context = {};
  if (status) {
    context = { status };
  } else if (session.status === 'ok') {
    context = { status: 'exited' };
  }

  updateSession(session, context);
}

/**
 * Serializes a passed session object to a JSON object with a slightly different structure.
 * This is necessary because the Sentry backend requires a slightly different schema of a session
 * than the one the JS SDKs use internally.
 *
 * @param session the session to be converted
 *
 * @returns a JSON object of the passed session
 */
function sessionToJSON(session) {
  return object_dropUndefinedKeys({
    sid: `${session.sid}`,
    init: session.init,
    // Make sure that sec is converted to ms for date constructor
    started: new Date(session.started * 1000).toISOString(),
    timestamp: new Date(session.timestamp * 1000).toISOString(),
    status: session.status,
    errors: session.errors,
    did: typeof session.did === 'number' || typeof session.did === 'string' ? `${session.did}` : undefined,
    duration: session.duration,
    abnormal_mechanism: session.abnormal_mechanism,
    attrs: {
      release: session.release,
      environment: session.environment,
      ip_address: session.ipAddress,
      user_agent: session.userAgent,
    },
  });
}


//# sourceMappingURL=session.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/propagationContext.js


/**
 * Returns a new minimal propagation context.
 *
 * @deprecated Use `generateTraceId` and `generateSpanId` instead.
 */
function generatePropagationContext() {
  return {
    traceId: generateTraceId(),
    spanId: generateSpanId(),
  };
}

/**
 * Generate a random, valid trace ID.
 */
function generateTraceId() {
  return misc_uuid4();
}

/**
 * Generate a random, valid span ID.
 */
function generateSpanId() {
  return misc_uuid4().substring(16);
}


//# sourceMappingURL=propagationContext.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/merge.js
/**
 * Shallow merge two objects.
 * Does not mutate the passed in objects.
 * Undefined/empty values in the merge object will overwrite existing values.
 *
 * By default, this merges 2 levels deep.
 */
function merge(initialObj, mergeObj, levels = 2) {
  // If the merge value is not an object, or we have no merge levels left,
  // we just set the value to the merge value
  if (!mergeObj || typeof mergeObj !== 'object' || levels <= 0) {
    return mergeObj;
  }

  // If the merge object is an empty object, and the initial object is not undefined, we return the initial object
  if (initialObj && mergeObj && Object.keys(mergeObj).length === 0) {
    return initialObj;
  }

  // Clone object
  const output = { ...initialObj };

  // Merge values into output, resursively
  for (const key in mergeObj) {
    if (Object.prototype.hasOwnProperty.call(mergeObj, key)) {
      output[key] = merge(output[key], mergeObj[key], levels - 1);
    }
  }

  return output;
}


//# sourceMappingURL=merge.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/spanOnScope.js


const SCOPE_SPAN_FIELD = '_sentrySpan';

/**
 * Set the active span for a given scope.
 * NOTE: This should NOT be used directly, but is only used internally by the trace methods.
 */
function _setSpanForScope(scope, span) {
  if (span) {
    object_addNonEnumerableProperty(scope , SCOPE_SPAN_FIELD, span);
  } else {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete (scope )[SCOPE_SPAN_FIELD];
  }
}

/**
 * Get the active span for a given scope.
 * NOTE: This should NOT be used directly, but is only used internally by the trace methods.
 */
function spanOnScope_getSpanForScope(scope) {
  return scope[SCOPE_SPAN_FIELD];
}


//# sourceMappingURL=spanOnScope.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/scope.js









/**
 * Default value for maximum number of breadcrumbs added to an event.
 */
const DEFAULT_MAX_BREADCRUMBS = 100;

/**
 * Holds additional event information.
 */
class ScopeClass  {
  /** Flag if notifying is happening. */

  /** Callback for client to receive scope changes. */

  /** Callback list that will be called during event processing. */

  /** Array of breadcrumbs. */

  /** User */

  /** Tags */

  /** Extra */

  /** Contexts */

  /** Attachments */

  /** Propagation Context for distributed tracing */

  /**
   * A place to stash data which is needed at some point in the SDK's event processing pipeline but which shouldn't get
   * sent to Sentry
   */

  /** Fingerprint */

  /** Severity */

  /**
   * Transaction Name
   *
   * IMPORTANT: The transaction name on the scope has nothing to do with root spans/transaction objects.
   * It's purpose is to assign a transaction to the scope that's added to non-transaction events.
   */

  /** Session */

  /** Request Mode Session Status */
  // eslint-disable-next-line deprecation/deprecation

  /** The client on this scope */

  /** Contains the last event id of a captured event.  */

  // NOTE: Any field which gets added here should get added not only to the constructor but also to the `clone` method.

   constructor() {
    this._notifyingListeners = false;
    this._scopeListeners = [];
    this._eventProcessors = [];
    this._breadcrumbs = [];
    this._attachments = [];
    this._user = {};
    this._tags = {};
    this._extra = {};
    this._contexts = {};
    this._sdkProcessingMetadata = {};
    this._propagationContext = {
      traceId: generateTraceId(),
      spanId: generateSpanId(),
    };
  }

  /**
   * @inheritDoc
   */
   clone() {
    const newScope = new ScopeClass();
    newScope._breadcrumbs = [...this._breadcrumbs];
    newScope._tags = { ...this._tags };
    newScope._extra = { ...this._extra };
    newScope._contexts = { ...this._contexts };
    if (this._contexts.flags) {
      // We need to copy the `values` array so insertions on a cloned scope
      // won't affect the original array.
      newScope._contexts.flags = {
        values: [...this._contexts.flags.values],
      };
    }

    newScope._user = this._user;
    newScope._level = this._level;
    newScope._session = this._session;
    newScope._transactionName = this._transactionName;
    newScope._fingerprint = this._fingerprint;
    newScope._eventProcessors = [...this._eventProcessors];
    newScope._requestSession = this._requestSession;
    newScope._attachments = [...this._attachments];
    newScope._sdkProcessingMetadata = { ...this._sdkProcessingMetadata };
    newScope._propagationContext = { ...this._propagationContext };
    newScope._client = this._client;
    newScope._lastEventId = this._lastEventId;

    _setSpanForScope(newScope, spanOnScope_getSpanForScope(this));

    return newScope;
  }

  /**
   * @inheritDoc
   */
   setClient(client) {
    this._client = client;
  }

  /**
   * @inheritDoc
   */
   setLastEventId(lastEventId) {
    this._lastEventId = lastEventId;
  }

  /**
   * @inheritDoc
   */
   getClient() {
    return this._client ;
  }

  /**
   * @inheritDoc
   */
   lastEventId() {
    return this._lastEventId;
  }

  /**
   * @inheritDoc
   */
   addScopeListener(callback) {
    this._scopeListeners.push(callback);
  }

  /**
   * @inheritDoc
   */
   addEventProcessor(callback) {
    this._eventProcessors.push(callback);
    return this;
  }

  /**
   * @inheritDoc
   */
   setUser(user) {
    // If null is passed we want to unset everything, but still define keys,
    // so that later down in the pipeline any existing values are cleared.
    this._user = user || {
      email: undefined,
      id: undefined,
      ip_address: undefined,
      username: undefined,
    };

    if (this._session) {
      updateSession(this._session, { user });
    }

    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   getUser() {
    return this._user;
  }

  /**
   * @inheritDoc
   */
  // eslint-disable-next-line deprecation/deprecation
   getRequestSession() {
    return this._requestSession;
  }

  /**
   * @inheritDoc
   */
  // eslint-disable-next-line deprecation/deprecation
   setRequestSession(requestSession) {
    this._requestSession = requestSession;
    return this;
  }

  /**
   * @inheritDoc
   */
   setTags(tags) {
    this._tags = {
      ...this._tags,
      ...tags,
    };
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setTag(key, value) {
    this._tags = { ...this._tags, [key]: value };
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setExtras(extras) {
    this._extra = {
      ...this._extra,
      ...extras,
    };
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setExtra(key, extra) {
    this._extra = { ...this._extra, [key]: extra };
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setFingerprint(fingerprint) {
    this._fingerprint = fingerprint;
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setLevel(level) {
    this._level = level;
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setTransactionName(name) {
    this._transactionName = name;
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setContext(key, context) {
    if (context === null) {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete this._contexts[key];
    } else {
      this._contexts[key] = context;
    }

    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   setSession(session) {
    if (!session) {
      delete this._session;
    } else {
      this._session = session;
    }
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   getSession() {
    return this._session;
  }

  /**
   * @inheritDoc
   */
   update(captureContext) {
    if (!captureContext) {
      return this;
    }

    const scopeToMerge = typeof captureContext === 'function' ? captureContext(this) : captureContext;

    const [scopeInstance, requestSession] =
      scopeToMerge instanceof Scope
        ? // eslint-disable-next-line deprecation/deprecation
          [scopeToMerge.getScopeData(), scopeToMerge.getRequestSession()]
        : isPlainObject(scopeToMerge)
          ? [captureContext , (captureContext ).requestSession]
          : [];

    const { tags, extra, user, contexts, level, fingerprint = [], propagationContext } = scopeInstance || {};

    this._tags = { ...this._tags, ...tags };
    this._extra = { ...this._extra, ...extra };
    this._contexts = { ...this._contexts, ...contexts };

    if (user && Object.keys(user).length) {
      this._user = user;
    }

    if (level) {
      this._level = level;
    }

    if (fingerprint.length) {
      this._fingerprint = fingerprint;
    }

    if (propagationContext) {
      this._propagationContext = propagationContext;
    }

    if (requestSession) {
      this._requestSession = requestSession;
    }

    return this;
  }

  /**
   * @inheritDoc
   */
   clear() {
    // client is not cleared here on purpose!
    this._breadcrumbs = [];
    this._tags = {};
    this._extra = {};
    this._user = {};
    this._contexts = {};
    this._level = undefined;
    this._transactionName = undefined;
    this._fingerprint = undefined;
    this._requestSession = undefined;
    this._session = undefined;
    _setSpanForScope(this, undefined);
    this._attachments = [];
    this.setPropagationContext({ traceId: generateTraceId() });

    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   addBreadcrumb(breadcrumb, maxBreadcrumbs) {
    const maxCrumbs = typeof maxBreadcrumbs === 'number' ? maxBreadcrumbs : DEFAULT_MAX_BREADCRUMBS;

    // No data has been changed, so don't notify scope listeners
    if (maxCrumbs <= 0) {
      return this;
    }

    const mergedBreadcrumb = {
      timestamp: dateTimestampInSeconds(),
      ...breadcrumb,
    };

    const breadcrumbs = this._breadcrumbs;
    breadcrumbs.push(mergedBreadcrumb);
    this._breadcrumbs = breadcrumbs.length > maxCrumbs ? breadcrumbs.slice(-maxCrumbs) : breadcrumbs;

    this._notifyScopeListeners();

    return this;
  }

  /**
   * @inheritDoc
   */
   getLastBreadcrumb() {
    return this._breadcrumbs[this._breadcrumbs.length - 1];
  }

  /**
   * @inheritDoc
   */
   clearBreadcrumbs() {
    this._breadcrumbs = [];
    this._notifyScopeListeners();
    return this;
  }

  /**
   * @inheritDoc
   */
   addAttachment(attachment) {
    this._attachments.push(attachment);
    return this;
  }

  /**
   * @inheritDoc
   */
   clearAttachments() {
    this._attachments = [];
    return this;
  }

  /** @inheritDoc */
   getScopeData() {
    return {
      breadcrumbs: this._breadcrumbs,
      attachments: this._attachments,
      contexts: this._contexts,
      tags: this._tags,
      extra: this._extra,
      user: this._user,
      level: this._level,
      fingerprint: this._fingerprint || [],
      eventProcessors: this._eventProcessors,
      propagationContext: this._propagationContext,
      sdkProcessingMetadata: this._sdkProcessingMetadata,
      transactionName: this._transactionName,
      span: spanOnScope_getSpanForScope(this),
    };
  }

  /**
   * @inheritDoc
   */
   setSDKProcessingMetadata(newData) {
    this._sdkProcessingMetadata = merge(this._sdkProcessingMetadata, newData, 2);
    return this;
  }

  /**
   * @inheritDoc
   */
   setPropagationContext(
    context,
  ) {
    this._propagationContext = {
      // eslint-disable-next-line deprecation/deprecation
      spanId: generateSpanId(),
      ...context,
    };
    return this;
  }

  /**
   * @inheritDoc
   */
   getPropagationContext() {
    return this._propagationContext;
  }

  /**
   * @inheritDoc
   */
   captureException(exception, hint) {
    const eventId = hint && hint.event_id ? hint.event_id : misc_uuid4();

    if (!this._client) {
      logger_logger.warn('No client configured on scope - will not capture exception!');
      return eventId;
    }

    const syntheticException = new Error('Sentry syntheticException');

    this._client.captureException(
      exception,
      {
        originalException: exception,
        syntheticException,
        ...hint,
        event_id: eventId,
      },
      this,
    );

    return eventId;
  }

  /**
   * @inheritDoc
   */
   captureMessage(message, level, hint) {
    const eventId = hint && hint.event_id ? hint.event_id : misc_uuid4();

    if (!this._client) {
      logger_logger.warn('No client configured on scope - will not capture message!');
      return eventId;
    }

    const syntheticException = new Error(message);

    this._client.captureMessage(
      message,
      level,
      {
        originalException: message,
        syntheticException,
        ...hint,
        event_id: eventId,
      },
      this,
    );

    return eventId;
  }

  /**
   * @inheritDoc
   */
   captureEvent(event, hint) {
    const eventId = hint && hint.event_id ? hint.event_id : misc_uuid4();

    if (!this._client) {
      logger_logger.warn('No client configured on scope - will not capture event!');
      return eventId;
    }

    this._client.captureEvent(event, { ...hint, event_id: eventId }, this);

    return eventId;
  }

  /**
   * This will be called on every set call.
   */
   _notifyScopeListeners() {
    // We need this check for this._notifyingListeners to be able to work on scope during updates
    // If this check is not here we'll produce endless recursion when something is done with the scope
    // during the callback.
    if (!this._notifyingListeners) {
      this._notifyingListeners = true;
      this._scopeListeners.forEach(callback => {
        callback(this);
      });
      this._notifyingListeners = false;
    }
  }
}

/**
 * Holds additional event information.
 */
const Scope = ScopeClass;

/**
 * Holds additional event information.
 */


//# sourceMappingURL=scope.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/defaultScopes.js



/** Get the default current scope. */
function getDefaultCurrentScope() {
  return getGlobalSingleton('defaultCurrentScope', () => new Scope());
}

/** Get the default isolation scope. */
function getDefaultIsolationScope() {
  return getGlobalSingleton('defaultIsolationScope', () => new Scope());
}


//# sourceMappingURL=defaultScopes.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/asyncContext/stackStrategy.js





/**
 * This is an object that holds a stack of scopes.
 */
class AsyncContextStack {

   constructor(scope, isolationScope) {
    let assignedScope;
    if (!scope) {
      assignedScope = new Scope();
    } else {
      assignedScope = scope;
    }

    let assignedIsolationScope;
    if (!isolationScope) {
      assignedIsolationScope = new Scope();
    } else {
      assignedIsolationScope = isolationScope;
    }

    // scope stack for domains or the process
    this._stack = [{ scope: assignedScope }];
    this._isolationScope = assignedIsolationScope;
  }

  /**
   * Fork a scope for the stack.
   */
   withScope(callback) {
    const scope = this._pushScope();

    let maybePromiseResult;
    try {
      maybePromiseResult = callback(scope);
    } catch (e) {
      this._popScope();
      throw e;
    }

    if (is_isThenable(maybePromiseResult)) {
      // @ts-expect-error - isThenable returns the wrong type
      return maybePromiseResult.then(
        res => {
          this._popScope();
          return res;
        },
        e => {
          this._popScope();
          throw e;
        },
      );
    }

    this._popScope();
    return maybePromiseResult;
  }

  /**
   * Get the client of the stack.
   */
   getClient() {
    return this.getStackTop().client ;
  }

  /**
   * Returns the scope of the top stack.
   */
   getScope() {
    return this.getStackTop().scope;
  }

  /**
   * Get the isolation scope for the stack.
   */
   getIsolationScope() {
    return this._isolationScope;
  }

  /**
   * Returns the topmost scope layer in the order domain > local > process.
   */
   getStackTop() {
    return this._stack[this._stack.length - 1] ;
  }

  /**
   * Push a scope to the stack.
   */
   _pushScope() {
    // We want to clone the content of prev scope
    const scope = this.getScope().clone();
    this._stack.push({
      client: this.getClient(),
      scope,
    });
    return scope;
  }

  /**
   * Pop a scope from the stack.
   */
   _popScope() {
    if (this._stack.length <= 1) return false;
    return !!this._stack.pop();
  }
}

/**
 * Get the global async context stack.
 * This will be removed during the v8 cycle and is only here to make migration easier.
 */
function getAsyncContextStack() {
  const registry = carrier_getMainCarrier();
  const sentry = carrier_getSentryCarrier(registry);

  return (sentry.stack = sentry.stack || new AsyncContextStack(getDefaultCurrentScope(), getDefaultIsolationScope()));
}

function withScope(callback) {
  return getAsyncContextStack().withScope(callback);
}

function withSetScope(scope, callback) {
  const stack = getAsyncContextStack() ;
  return stack.withScope(() => {
    stack.getStackTop().scope = scope;
    return callback(scope);
  });
}

function stackStrategy_withIsolationScope(callback) {
  return getAsyncContextStack().withScope(() => {
    return callback(getAsyncContextStack().getIsolationScope());
  });
}

/**
 * Get the stack-based async context strategy.
 */
function getStackAsyncContextStrategy() {
  return {
    withIsolationScope: stackStrategy_withIsolationScope,
    withScope,
    withSetScope,
    withSetIsolationScope: (_isolationScope, callback) => {
      return stackStrategy_withIsolationScope(callback);
    },
    getCurrentScope: () => getAsyncContextStack().getScope(),
    getIsolationScope: () => getAsyncContextStack().getIsolationScope(),
  };
}


//# sourceMappingURL=stackStrategy.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/asyncContext/index.js



/**
 * @private Private API with no semver guarantees!
 *
 * Sets the global async context strategy
 */
function setAsyncContextStrategy(strategy) {
  // Get main carrier (global for every environment)
  const registry = getMainCarrier();
  const sentry = getSentryCarrier(registry);
  sentry.acs = strategy;
}

/**
 * Get the current async context strategy.
 * If none has been setup, the default will be used.
 */
function asyncContext_getAsyncContextStrategy(carrier) {
  const sentry = carrier_getSentryCarrier(carrier);

  if (sentry.acs) {
    return sentry.acs;
  }

  // Otherwise, use the default one (stack)
  return getStackAsyncContextStrategy();
}


//# sourceMappingURL=index.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/currentScopes.js






/**
 * Get the currently active scope.
 */
function currentScopes_getCurrentScope() {
  const carrier = carrier_getMainCarrier();
  const acs = asyncContext_getAsyncContextStrategy(carrier);
  return acs.getCurrentScope();
}

/**
 * Get the currently active isolation scope.
 * The isolation scope is active for the current execution context.
 */
function currentScopes_getIsolationScope() {
  const carrier = carrier_getMainCarrier();
  const acs = asyncContext_getAsyncContextStrategy(carrier);
  return acs.getIsolationScope();
}

/**
 * Get the global scope.
 * This scope is applied to _all_ events.
 */
function getGlobalScope() {
  return getGlobalSingleton('globalScope', () => new Scope());
}

/**
 * Creates a new scope with and executes the given operation within.
 * The scope is automatically removed once the operation
 * finishes or throws.
 */

/**
 * Either creates a new active scope, or sets the given scope as active scope in the given callback.
 */
function currentScopes_withScope(
  ...rest
) {
  const carrier = carrier_getMainCarrier();
  const acs = asyncContext_getAsyncContextStrategy(carrier);

  // If a scope is defined, we want to make this the active scope instead of the default one
  if (rest.length === 2) {
    const [scope, callback] = rest;

    if (!scope) {
      return acs.withScope(callback);
    }

    return acs.withSetScope(scope, callback);
  }

  return acs.withScope(rest[0]);
}

/**
 * Attempts to fork the current isolation scope and the current scope based on the current async context strategy. If no
 * async context strategy is set, the isolation scope and the current scope will not be forked (this is currently the
 * case, for example, in the browser).
 *
 * Usage of this function in environments without async context strategy is discouraged and may lead to unexpected behaviour.
 *
 * This function is intended for Sentry SDK and SDK integration development. It is not recommended to be used in "normal"
 * applications directly because it comes with pitfalls. Use at your own risk!
 */

/**
 * Either creates a new active isolation scope, or sets the given isolation scope as active scope in the given callback.
 */
function currentScopes_withIsolationScope(
  ...rest

) {
  const carrier = getMainCarrier();
  const acs = getAsyncContextStrategy(carrier);

  // If a scope is defined, we want to make this the active scope instead of the default one
  if (rest.length === 2) {
    const [isolationScope, callback] = rest;

    if (!isolationScope) {
      return acs.withIsolationScope(callback);
    }

    return acs.withSetIsolationScope(isolationScope, callback);
  }

  return acs.withIsolationScope(rest[0]);
}

/**
 * Get the currently active client.
 */
function currentScopes_getClient() {
  return currentScopes_getCurrentScope().getClient();
}

/**
 * Get a trace context for the given scope.
 */
function getTraceContextFromScope(scope) {
  const propagationContext = scope.getPropagationContext();

  // TODO(v9): Use generateSpanId() instead of spanId
  // eslint-disable-next-line deprecation/deprecation
  const { traceId, spanId, parentSpanId } = propagationContext;

  const traceContext = object_dropUndefinedKeys({
    trace_id: traceId,
    span_id: spanId,
    parent_span_id: parentSpanId,
  });

  return traceContext;
}


//# sourceMappingURL=currentScopes.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/integrations/functiontostring.js




let originalFunctionToString;

const functiontostring_INTEGRATION_NAME = 'FunctionToString';

const SETUP_CLIENTS = new WeakMap();

const _functionToStringIntegration = (() => {
  return {
    name: functiontostring_INTEGRATION_NAME,
    setupOnce() {
      // eslint-disable-next-line @typescript-eslint/unbound-method
      originalFunctionToString = Function.prototype.toString;

      // intrinsics (like Function.prototype) might be immutable in some environments
      // e.g. Node with --frozen-intrinsics, XS (an embedded JavaScript engine) or SES (a JavaScript proposal)
      try {
        Function.prototype.toString = function ( ...args) {
          const originalFunction = getOriginalFunction(this);
          const context =
            SETUP_CLIENTS.has(currentScopes_getClient() ) && originalFunction !== undefined ? originalFunction : this;
          return originalFunctionToString.apply(context, args);
        };
      } catch (e) {
        // ignore errors here, just don't patch this
      }
    },
    setup(client) {
      SETUP_CLIENTS.set(client, true);
    },
  };
}) ;

/**
 * Patch toString calls to return proper name for wrapped functions.
 *
 * ```js
 * Sentry.init({
 *   integrations: [
 *     functionToStringIntegration(),
 *   ],
 * });
 * ```
 */
const functionToStringIntegration = defineIntegration(_functionToStringIntegration);


//# sourceMappingURL=functiontostring.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/stacktrace.js
const STACKTRACE_FRAME_LIMIT = 50;
const UNKNOWN_FUNCTION = '?';
// Used to sanitize webpack (error: *) wrapped stack errors
const WEBPACK_ERROR_REGEXP = /\(error: (.*)\)/;
const STRIP_FRAME_REGEXP = /captureMessage|captureException/;

/**
 * Creates a stack parser with the supplied line parsers
 *
 * StackFrames are returned in the correct order for Sentry Exception
 * frames and with Sentry SDK internal frames removed from the top and bottom
 *
 */
function createStackParser(...parsers) {
  const sortedParsers = parsers.sort((a, b) => a[0] - b[0]).map(p => p[1]);

  return (stack, skipFirstLines = 0, framesToPop = 0) => {
    const frames = [];
    const lines = stack.split('\n');

    for (let i = skipFirstLines; i < lines.length; i++) {
      const line = lines[i] ;
      // Ignore lines over 1kb as they are unlikely to be stack frames.
      // Many of the regular expressions use backtracking which results in run time that increases exponentially with
      // input size. Huge strings can result in hangs/Denial of Service:
      // https://github.com/getsentry/sentry-javascript/issues/2286
      if (line.length > 1024) {
        continue;
      }

      // https://github.com/getsentry/sentry-javascript/issues/5459
      // Remove webpack (error: *) wrappers
      const cleanedLine = WEBPACK_ERROR_REGEXP.test(line) ? line.replace(WEBPACK_ERROR_REGEXP, '$1') : line;

      // https://github.com/getsentry/sentry-javascript/issues/7813
      // Skip Error: lines
      if (cleanedLine.match(/\S*Error: /)) {
        continue;
      }

      for (const parser of sortedParsers) {
        const frame = parser(cleanedLine);

        if (frame) {
          frames.push(frame);
          break;
        }
      }

      if (frames.length >= STACKTRACE_FRAME_LIMIT + framesToPop) {
        break;
      }
    }

    return stripSentryFramesAndReverse(frames.slice(framesToPop));
  };
}

/**
 * Gets a stack parser implementation from Options.stackParser
 * @see Options
 *
 * If options contains an array of line parsers, it is converted into a parser
 */
function stackParserFromStackParserOptions(stackParser) {
  if (Array.isArray(stackParser)) {
    return createStackParser(...stackParser);
  }
  return stackParser;
}

/**
 * Removes Sentry frames from the top and bottom of the stack if present and enforces a limit of max number of frames.
 * Assumes stack input is ordered from top to bottom and returns the reverse representation so call site of the
 * function that caused the crash is the last frame in the array.
 * @hidden
 */
function stripSentryFramesAndReverse(stack) {
  if (!stack.length) {
    return [];
  }

  const localStack = Array.from(stack);

  // If stack starts with one of our API calls, remove it (starts, meaning it's the top of the stack - aka last call)
  if (/sentryWrapped/.test(getLastStackFrame(localStack).function || '')) {
    localStack.pop();
  }

  // Reversing in the middle of the procedure allows us to just pop the values off the stack
  localStack.reverse();

  // If stack ends with one of our internal API calls, remove it (ends, meaning it's the bottom of the stack - aka top-most call)
  if (STRIP_FRAME_REGEXP.test(getLastStackFrame(localStack).function || '')) {
    localStack.pop();

    // When using synthetic events, we will have a 2 levels deep stack, as `new Error('Sentry syntheticException')`
    // is produced within the hub itself, making it:
    //
    //   Sentry.captureException()
    //   getCurrentHub().captureException()
    //
    // instead of just the top `Sentry` call itself.
    // This forces us to possibly strip an additional frame in the exact same was as above.
    if (STRIP_FRAME_REGEXP.test(getLastStackFrame(localStack).function || '')) {
      localStack.pop();
    }
  }

  return localStack.slice(0, STACKTRACE_FRAME_LIMIT).map(frame => ({
    ...frame,
    filename: frame.filename || getLastStackFrame(localStack).filename,
    function: frame.function || UNKNOWN_FUNCTION,
  }));
}

function getLastStackFrame(arr) {
  return arr[arr.length - 1] || {};
}

const defaultFunctionName = '<anonymous>';

/**
 * Safely extract function name from itself
 */
function getFunctionName(fn) {
  try {
    if (!fn || typeof fn !== 'function') {
      return defaultFunctionName;
    }
    return fn.name || defaultFunctionName;
  } catch (e) {
    // Just accessing custom props in some Selenium environments
    // can cause a "Permission denied" exception (see raven-js#495).
    return defaultFunctionName;
  }
}

/**
 * Get's stack frames from an event without needing to check for undefined properties.
 */
function getFramesFromEvent(event) {
  const exception = event.exception;

  if (exception) {
    const frames = [];
    try {
      // @ts-expect-error Object could be undefined
      exception.values.forEach(value => {
        // @ts-expect-error Value could be undefined
        if (value.stacktrace.frames) {
          // @ts-expect-error Value could be undefined
          frames.push(...value.stacktrace.frames);
        }
      });
      return frames;
    } catch (_oO) {
      return undefined;
    }
  }
  return undefined;
}


//# sourceMappingURL=stacktrace.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/integrations/dedupe.js





const dedupe_INTEGRATION_NAME = 'Dedupe';

const _dedupeIntegration = (() => {
  let previousEvent;

  return {
    name: dedupe_INTEGRATION_NAME,
    processEvent(currentEvent) {
      // We want to ignore any non-error type events, e.g. transactions or replays
      // These should never be deduped, and also not be compared against as _previousEvent.
      if (currentEvent.type) {
        return currentEvent;
      }

      // Juuust in case something goes wrong
      try {
        if (dedupe_shouldDropEvent(currentEvent, previousEvent)) {
          debug_build_DEBUG_BUILD && logger_logger.warn('Event dropped due to being a duplicate of previously captured event.');
          return null;
        }
      } catch (_oO) {} // eslint-disable-line no-empty

      return (previousEvent = currentEvent);
    },
  };
}) ;

/**
 * Deduplication filter.
 */
const dedupeIntegration = defineIntegration(_dedupeIntegration);

/** only exported for tests. */
function dedupe_shouldDropEvent(currentEvent, previousEvent) {
  if (!previousEvent) {
    return false;
  }

  if (_isSameMessageEvent(currentEvent, previousEvent)) {
    return true;
  }

  if (_isSameExceptionEvent(currentEvent, previousEvent)) {
    return true;
  }

  return false;
}

function _isSameMessageEvent(currentEvent, previousEvent) {
  const currentMessage = currentEvent.message;
  const previousMessage = previousEvent.message;

  // If neither event has a message property, they were both exceptions, so bail out
  if (!currentMessage && !previousMessage) {
    return false;
  }

  // If only one event has a stacktrace, but not the other one, they are not the same
  if ((currentMessage && !previousMessage) || (!currentMessage && previousMessage)) {
    return false;
  }

  if (currentMessage !== previousMessage) {
    return false;
  }

  if (!_isSameFingerprint(currentEvent, previousEvent)) {
    return false;
  }

  if (!_isSameStacktrace(currentEvent, previousEvent)) {
    return false;
  }

  return true;
}

function _isSameExceptionEvent(currentEvent, previousEvent) {
  const previousException = _getExceptionFromEvent(previousEvent);
  const currentException = _getExceptionFromEvent(currentEvent);

  if (!previousException || !currentException) {
    return false;
  }

  if (previousException.type !== currentException.type || previousException.value !== currentException.value) {
    return false;
  }

  if (!_isSameFingerprint(currentEvent, previousEvent)) {
    return false;
  }

  if (!_isSameStacktrace(currentEvent, previousEvent)) {
    return false;
  }

  return true;
}

function _isSameStacktrace(currentEvent, previousEvent) {
  let currentFrames = getFramesFromEvent(currentEvent);
  let previousFrames = getFramesFromEvent(previousEvent);

  // If neither event has a stacktrace, they are assumed to be the same
  if (!currentFrames && !previousFrames) {
    return true;
  }

  // If only one event has a stacktrace, but not the other one, they are not the same
  if ((currentFrames && !previousFrames) || (!currentFrames && previousFrames)) {
    return false;
  }

  currentFrames = currentFrames ;
  previousFrames = previousFrames ;

  // If number of frames differ, they are not the same
  if (previousFrames.length !== currentFrames.length) {
    return false;
  }

  // Otherwise, compare the two
  for (let i = 0; i < previousFrames.length; i++) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const frameA = previousFrames[i];
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const frameB = currentFrames[i];

    if (
      frameA.filename !== frameB.filename ||
      frameA.lineno !== frameB.lineno ||
      frameA.colno !== frameB.colno ||
      frameA.function !== frameB.function
    ) {
      return false;
    }
  }

  return true;
}

function _isSameFingerprint(currentEvent, previousEvent) {
  let currentFingerprint = currentEvent.fingerprint;
  let previousFingerprint = previousEvent.fingerprint;

  // If neither event has a fingerprint, they are assumed to be the same
  if (!currentFingerprint && !previousFingerprint) {
    return true;
  }

  // If only one event has a fingerprint, but not the other one, they are not the same
  if ((currentFingerprint && !previousFingerprint) || (!currentFingerprint && previousFingerprint)) {
    return false;
  }

  currentFingerprint = currentFingerprint ;
  previousFingerprint = previousFingerprint ;

  // Otherwise, compare the two
  try {
    return !!(currentFingerprint.join('') === previousFingerprint.join(''));
  } catch (_oO) {
    return false;
  }
}

function _getExceptionFromEvent(event) {
  return event.exception && event.exception.values && event.exception.values[0];
}


//# sourceMappingURL=dedupe.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/supports.js




const supports_WINDOW = worldwide_GLOBAL_OBJ ;

/**
 * Tells whether current environment supports ErrorEvent objects
 * {@link supportsErrorEvent}.
 *
 * @returns Answer to the given question.
 */
function supportsErrorEvent() {
  try {
    new ErrorEvent('');
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Tells whether current environment supports DOMError objects
 * {@link supportsDOMError}.
 *
 * @returns Answer to the given question.
 */
function supportsDOMError() {
  try {
    // Chrome: VM89:1 Uncaught TypeError: Failed to construct 'DOMError':
    // 1 argument required, but only 0 present.
    // @ts-expect-error It really needs 1 argument, not 0.
    new DOMError('');
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Tells whether current environment supports DOMException objects
 * {@link supportsDOMException}.
 *
 * @returns Answer to the given question.
 */
function supportsDOMException() {
  try {
    new DOMException('');
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Tells whether current environment supports Fetch API
 * {@link supportsFetch}.
 *
 * @returns Answer to the given question.
 */
function supportsFetch() {
  if (!('fetch' in supports_WINDOW)) {
    return false;
  }

  try {
    new Headers();
    new Request('http://www.example.com');
    new Response();
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * isNative checks if the given function is a native implementation
 */
// eslint-disable-next-line @typescript-eslint/ban-types
function isNativeFunction(func) {
  return func && /^function\s+\w+\(\)\s+\{\s+\[native code\]\s+\}$/.test(func.toString());
}

/**
 * Tells whether current environment supports Fetch API natively
 * {@link supportsNativeFetch}.
 *
 * @returns true if `window.fetch` is natively implemented, false otherwise
 */
function supportsNativeFetch() {
  if (typeof EdgeRuntime === 'string') {
    return true;
  }

  if (!supportsFetch()) {
    return false;
  }

  // Fast path to avoid DOM I/O
  // eslint-disable-next-line @typescript-eslint/unbound-method
  if (isNativeFunction(supports_WINDOW.fetch)) {
    return true;
  }

  // window.fetch is implemented, but is polyfilled or already wrapped (e.g: by a chrome extension)
  // so create a "pure" iframe to see if that has native fetch
  let result = false;
  const doc = supports_WINDOW.document;
  // eslint-disable-next-line deprecation/deprecation
  if (doc && typeof (doc.createElement ) === 'function') {
    try {
      const sandbox = doc.createElement('iframe');
      sandbox.hidden = true;
      doc.head.appendChild(sandbox);
      if (sandbox.contentWindow && sandbox.contentWindow.fetch) {
        // eslint-disable-next-line @typescript-eslint/unbound-method
        result = isNativeFunction(sandbox.contentWindow.fetch);
      }
      doc.head.removeChild(sandbox);
    } catch (err) {
      utils_hoist_debug_build_DEBUG_BUILD &&
        logger_logger.warn('Could not create sandbox iframe for pure fetch check, bailing to window.fetch: ', err);
    }
  }

  return result;
}

/**
 * Tells whether current environment supports ReportingObserver API
 * {@link supportsReportingObserver}.
 *
 * @returns Answer to the given question.
 */
function supportsReportingObserver() {
  return 'ReportingObserver' in supports_WINDOW;
}

/**
 * Tells whether current environment supports Referrer Policy API
 * {@link supportsReferrerPolicy}.
 *
 * @returns Answer to the given question.
 */
function supportsReferrerPolicy() {
  // Despite all stars in the sky saying that Edge supports old draft syntax, aka 'never', 'always', 'origin' and 'default'
  // (see https://caniuse.com/#feat=referrer-policy),
  // it doesn't. And it throws an exception instead of ignoring this parameter...
  // REF: https://github.com/getsentry/raven-js/issues/1233

  if (!supportsFetch()) {
    return false;
  }

  try {
    new Request('_', {
      referrerPolicy: 'origin' ,
    });
    return true;
  } catch (e) {
    return false;
  }
}


//# sourceMappingURL=supports.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/sdk.js




/** A class object that can instantiate Client objects. */

/**
 * Internal function to create a new SDK client instance. The client is
 * installed and then bound to the current scope.
 *
 * @param clientClass The client class to instantiate.
 * @param options Options to pass to the client.
 */
function initAndBind(
  clientClass,
  options,
) {
  if (options.debug === true) {
    if (debug_build_DEBUG_BUILD) {
      logger_logger.enable();
    } else {
      // use `console.warn` rather than `logger.warn` since by non-debug bundles have all `logger.x` statements stripped
      consoleSandbox(() => {
        // eslint-disable-next-line no-console
        console.warn('[Sentry] Cannot initialize SDK with `debug` option using a non-debug bundle.');
      });
    }
  }
  const scope = currentScopes_getCurrentScope();
  scope.update(options.initialScope);

  const client = new clientClass(options);
  setCurrentClient(client);
  client.init();
  return client;
}

/**
 * Make the given client the current client.
 */
function setCurrentClient(client) {
  currentScopes_getCurrentScope().setClient(client);
}


//# sourceMappingURL=sdk.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/api.js


const SENTRY_API_VERSION = '7';

/** Returns the prefix to construct Sentry ingestion API endpoints. */
function getBaseApiEndpoint(dsn) {
  const protocol = dsn.protocol ? `${dsn.protocol}:` : '';
  const port = dsn.port ? `:${dsn.port}` : '';
  return `${protocol}//${dsn.host}${port}${dsn.path ? `/${dsn.path}` : ''}/api/`;
}

/** Returns the ingest API endpoint for target. */
function _getIngestEndpoint(dsn) {
  return `${getBaseApiEndpoint(dsn)}${dsn.projectId}/envelope/`;
}

/** Returns a URL-encoded string with auth config suitable for a query string. */
function _encodedAuth(dsn, sdkInfo) {
  const params = {
    sentry_version: SENTRY_API_VERSION,
  };

  if (dsn.publicKey) {
    // We send only the minimum set of required information. See
    // https://github.com/getsentry/sentry-javascript/issues/2572.
    params.sentry_key = dsn.publicKey;
  }

  if (sdkInfo) {
    params.sentry_client = `${sdkInfo.name}/${sdkInfo.version}`;
  }

  return new URLSearchParams(params).toString();
}

/**
 * Returns the envelope endpoint URL with auth in the query string.
 *
 * Sending auth as part of the query string and not as custom HTTP headers avoids CORS preflight requests.
 */
function getEnvelopeEndpointWithUrlEncodedAuth(dsn, tunnel, sdkInfo) {
  return tunnel ? tunnel : `${_getIngestEndpoint(dsn)}?${_encodedAuth(dsn, sdkInfo)}`;
}

/** Returns the url to the report dialog endpoint. */
function api_getReportDialogEndpoint(
  dsnLike,
  dialogOptions

,
) {
  const dsn = makeDsn(dsnLike);
  if (!dsn) {
    return '';
  }

  const endpoint = `${getBaseApiEndpoint(dsn)}embed/error-page/`;

  let encodedOptions = `dsn=${dsnToString(dsn)}`;
  for (const key in dialogOptions) {
    if (key === 'dsn') {
      continue;
    }

    if (key === 'onClose') {
      continue;
    }

    if (key === 'user') {
      const user = dialogOptions.user;
      if (!user) {
        continue;
      }
      if (user.name) {
        encodedOptions += `&name=${encodeURIComponent(user.name)}`;
      }
      if (user.email) {
        encodedOptions += `&email=${encodeURIComponent(user.email)}`;
      }
    } else {
      encodedOptions += `&${encodeURIComponent(key)}=${encodeURIComponent(dialogOptions[key] )}`;
    }
  }

  return `${endpoint}?${encodedOptions}`;
}


//# sourceMappingURL=api.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/dsn.js



/** Regular expression used to parse a Dsn. */
const DSN_REGEX = /^(?:(\w+):)\/\/(?:(\w+)(?::(\w+)?)?@)([\w.-]+)(?::(\d+))?\/(.+)/;

function isValidProtocol(protocol) {
  return protocol === 'http' || protocol === 'https';
}

/**
 * Renders the string representation of this Dsn.
 *
 * By default, this will render the public representation without the password
 * component. To get the deprecated private representation, set `withPassword`
 * to true.
 *
 * @param withPassword When set to true, the password will be included.
 */
function dsn_dsnToString(dsn, withPassword = false) {
  const { host, path, pass, port, projectId, protocol, publicKey } = dsn;
  return (
    `${protocol}://${publicKey}${withPassword && pass ? `:${pass}` : ''}` +
    `@${host}${port ? `:${port}` : ''}/${path ? `${path}/` : path}${projectId}`
  );
}

/**
 * Parses a Dsn from a given string.
 *
 * @param str A Dsn as string
 * @returns Dsn as DsnComponents or undefined if @param str is not a valid DSN string
 */
function dsnFromString(str) {
  const match = DSN_REGEX.exec(str);

  if (!match) {
    // This should be logged to the console
    consoleSandbox(() => {
      // eslint-disable-next-line no-console
      console.error(`Invalid Sentry Dsn: ${str}`);
    });
    return undefined;
  }

  const [protocol, publicKey, pass = '', host = '', port = '', lastPath = ''] = match.slice(1);
  let path = '';
  let projectId = lastPath;

  const split = projectId.split('/');
  if (split.length > 1) {
    path = split.slice(0, -1).join('/');
    projectId = split.pop() ;
  }

  if (projectId) {
    const projectMatch = projectId.match(/^\d+/);
    if (projectMatch) {
      projectId = projectMatch[0];
    }
  }

  return dsnFromComponents({ host, pass, path, projectId, port, protocol: protocol , publicKey });
}

function dsnFromComponents(components) {
  return {
    protocol: components.protocol,
    publicKey: components.publicKey || '',
    pass: components.pass || '',
    host: components.host,
    port: components.port || '',
    path: components.path || '',
    projectId: components.projectId,
  };
}

function validateDsn(dsn) {
  if (!utils_hoist_debug_build_DEBUG_BUILD) {
    return true;
  }

  const { port, projectId, protocol } = dsn;

  const requiredComponents = ['protocol', 'publicKey', 'host', 'projectId'];
  const hasMissingRequiredComponent = requiredComponents.find(component => {
    if (!dsn[component]) {
      logger_logger.error(`Invalid Sentry Dsn: ${component} missing`);
      return true;
    }
    return false;
  });

  if (hasMissingRequiredComponent) {
    return false;
  }

  if (!projectId.match(/^\d+$/)) {
    logger_logger.error(`Invalid Sentry Dsn: Invalid projectId ${projectId}`);
    return false;
  }

  if (!isValidProtocol(protocol)) {
    logger_logger.error(`Invalid Sentry Dsn: Invalid protocol ${protocol}`);
    return false;
  }

  if (port && isNaN(parseInt(port, 10))) {
    logger_logger.error(`Invalid Sentry Dsn: Invalid port ${port}`);
    return false;
  }

  return true;
}

/**
 * Creates a valid Sentry Dsn object, identifying a Sentry instance and project.
 * @returns a valid DsnComponents object or `undefined` if @param from is an invalid DSN source
 */
function dsn_makeDsn(from) {
  const components = typeof from === 'string' ? dsnFromString(from) : dsnFromComponents(from);
  if (!components || !validateDsn(components)) {
    return undefined;
  }
  return components;
}


//# sourceMappingURL=dsn.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/memo.js
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Helper to decycle json objects
 *
 * @deprecated This function is deprecated and will be removed in the next major version.
 */
// TODO(v9): Move this function into normalize() directly
function memoBuilder() {
  const hasWeakSet = typeof WeakSet === 'function';
  const inner = hasWeakSet ? new WeakSet() : [];
  function memoize(obj) {
    if (hasWeakSet) {
      if (inner.has(obj)) {
        return true;
      }
      inner.add(obj);
      return false;
    }
    // eslint-disable-next-line @typescript-eslint/prefer-for-of
    for (let i = 0; i < inner.length; i++) {
      const value = inner[i];
      if (value === obj) {
        return true;
      }
    }
    inner.push(obj);
    return false;
  }

  function unmemoize(obj) {
    if (hasWeakSet) {
      inner.delete(obj);
    } else {
      for (let i = 0; i < inner.length; i++) {
        if (inner[i] === obj) {
          inner.splice(i, 1);
          break;
        }
      }
    }
  }
  return [memoize, unmemoize];
}


//# sourceMappingURL=memo.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/normalize.js





/**
 * Recursively normalizes the given object.
 *
 * - Creates a copy to prevent original input mutation
 * - Skips non-enumerable properties
 * - When stringifying, calls `toJSON` if implemented
 * - Removes circular references
 * - Translates non-serializable values (`undefined`/`NaN`/functions) to serializable format
 * - Translates known global objects/classes to a string representations
 * - Takes care of `Error` object serialization
 * - Optionally limits depth of final output
 * - Optionally limits number of properties/elements included in any single object/array
 *
 * @param input The object to be normalized.
 * @param depth The max depth to which to normalize the object. (Anything deeper stringified whole.)
 * @param maxProperties The max number of elements or properties to be included in any single array or
 * object in the normalized output.
 * @returns A normalized version of the object, or `"**non-serializable**"` if any errors are thrown during normalization.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalize(input, depth = 100, maxProperties = +Infinity) {
  try {
    // since we're at the outermost level, we don't provide a key
    return visit('', input, depth, maxProperties);
  } catch (err) {
    return { ERROR: `**non-serializable** (${err})` };
  }
}

/** JSDoc */
function normalizeToSize(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  object,
  // Default Node.js REPL depth
  depth = 3,
  // 100kB, as 200kB is max payload size, so half sounds reasonable
  maxSize = 100 * 1024,
) {
  const normalized = normalize(object, depth);

  if (jsonSize(normalized) > maxSize) {
    return normalizeToSize(object, depth - 1, maxSize);
  }

  return normalized ;
}

/**
 * Visits a node to perform normalization on it
 *
 * @param key The key corresponding to the given node
 * @param value The node to be visited
 * @param depth Optional number indicating the maximum recursion depth
 * @param maxProperties Optional maximum number of properties/elements included in any single object/array
 * @param memo Optional Memo class handling decycling
 */
function visit(
  key,
  value,
  depth = +Infinity,
  maxProperties = +Infinity,
  // eslint-disable-next-line deprecation/deprecation
  memo = memoBuilder(),
) {
  const [memoize, unmemoize] = memo;

  // Get the simple cases out of the way first
  if (
    value == null || // this matches null and undefined -> eqeq not eqeqeq
    ['boolean', 'string'].includes(typeof value) ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value ;
  }

  const stringified = stringifyValue(key, value);

  // Anything we could potentially dig into more (objects or arrays) will have come back as `"[object XXXX]"`.
  // Everything else will have already been serialized, so if we don't see that pattern, we're done.
  if (!stringified.startsWith('[object ')) {
    return stringified;
  }

  // From here on, we can assert that `value` is either an object or an array.

  // Do not normalize objects that we know have already been normalized. As a general rule, the
  // "__sentry_skip_normalization__" property should only be used sparingly and only should only be set on objects that
  // have already been normalized.
  if ((value )['__sentry_skip_normalization__']) {
    return value ;
  }

  // We can set `__sentry_override_normalization_depth__` on an object to ensure that from there
  // We keep a certain amount of depth.
  // This should be used sparingly, e.g. we use it for the redux integration to ensure we get a certain amount of state.
  const remainingDepth =
    typeof (value )['__sentry_override_normalization_depth__'] === 'number'
      ? ((value )['__sentry_override_normalization_depth__'] )
      : depth;

  // We're also done if we've reached the max depth
  if (remainingDepth === 0) {
    // At this point we know `serialized` is a string of the form `"[object XXXX]"`. Clean it up so it's just `"[XXXX]"`.
    return stringified.replace('object ', '');
  }

  // If we've already visited this branch, bail out, as it's circular reference. If not, note that we're seeing it now.
  if (memoize(value)) {
    return '[Circular ~]';
  }

  // If the value has a `toJSON` method, we call it to extract more information
  const valueWithToJSON = value ;
  if (valueWithToJSON && typeof valueWithToJSON.toJSON === 'function') {
    try {
      const jsonValue = valueWithToJSON.toJSON();
      // We need to normalize the return value of `.toJSON()` in case it has circular references
      return visit('', jsonValue, remainingDepth - 1, maxProperties, memo);
    } catch (err) {
      // pass (The built-in `toJSON` failed, but we can still try to do it ourselves)
    }
  }

  // At this point we know we either have an object or an array, we haven't seen it before, and we're going to recurse
  // because we haven't yet reached the max depth. Create an accumulator to hold the results of visiting each
  // property/entry, and keep track of the number of items we add to it.
  const normalized = (Array.isArray(value) ? [] : {}) ;
  let numAdded = 0;

  // Before we begin, convert`Error` and`Event` instances into plain objects, since some of each of their relevant
  // properties are non-enumerable and otherwise would get missed.
  const visitable = convertToPlainObject(value );

  for (const visitKey in visitable) {
    // Avoid iterating over fields in the prototype if they've somehow been exposed to enumeration.
    if (!Object.prototype.hasOwnProperty.call(visitable, visitKey)) {
      continue;
    }

    if (numAdded >= maxProperties) {
      normalized[visitKey] = '[MaxProperties ~]';
      break;
    }

    // Recursively visit all the child nodes
    const visitValue = visitable[visitKey];
    normalized[visitKey] = visit(visitKey, visitValue, remainingDepth - 1, maxProperties, memo);

    numAdded++;
  }

  // Once we've visited all the branches, remove the parent from memo storage
  unmemoize(value);

  // Return accumulated values
  return normalized;
}

/* eslint-disable complexity */
/**
 * Stringify the given value. Handles various known special values and types.
 *
 * Not meant to be used on simple primitives which already have a string representation, as it will, for example, turn
 * the number 1231 into "[Object Number]", nor on `null`, as it will throw.
 *
 * @param value The value to stringify
 * @returns A stringified representation of the given value
 */
function stringifyValue(
  key,
  // this type is a tiny bit of a cheat, since this function does handle NaN (which is technically a number), but for
  // our internal use, it'll do
  value,
) {
  try {
    if (key === 'domain' && value && typeof value === 'object' && (value )._events) {
      return '[Domain]';
    }

    if (key === 'domainEmitter') {
      return '[DomainEmitter]';
    }

    // It's safe to use `global`, `window`, and `document` here in this manner, as we are asserting using `typeof` first
    // which won't throw if they are not present.

    if (typeof global !== 'undefined' && value === global) {
      return '[Global]';
    }

    // eslint-disable-next-line no-restricted-globals
    if (typeof window !== 'undefined' && value === window) {
      return '[Window]';
    }

    // eslint-disable-next-line no-restricted-globals
    if (typeof document !== 'undefined' && value === document) {
      return '[Document]';
    }

    if (isVueViewModel(value)) {
      return '[VueViewModel]';
    }

    // React's SyntheticEvent thingy
    if (isSyntheticEvent(value)) {
      return '[SyntheticEvent]';
    }

    if (typeof value === 'number' && !Number.isFinite(value)) {
      return `[${value}]`;
    }

    if (typeof value === 'function') {
      return `[Function: ${getFunctionName(value)}]`;
    }

    if (typeof value === 'symbol') {
      return `[${String(value)}]`;
    }

    // stringified BigInts are indistinguishable from regular numbers, so we need to label them to avoid confusion
    if (typeof value === 'bigint') {
      return `[BigInt: ${String(value)}]`;
    }

    // Now that we've knocked out all the special cases and the primitives, all we have left are objects. Simply casting
    // them to strings means that instances of classes which haven't defined their `toStringTag` will just come out as
    // `"[object Object]"`. If we instead look at the constructor's name (which is the same as the name of the class),
    // we can make sure that only plain objects come out that way.
    const objName = getConstructorName(value);

    // Handle HTML Elements
    if (/^HTML(\w*)Element$/.test(objName)) {
      return `[HTMLElement: ${objName}]`;
    }

    return `[object ${objName}]`;
  } catch (err) {
    return `**non-serializable** (${err})`;
  }
}
/* eslint-enable complexity */

function getConstructorName(value) {
  const prototype = Object.getPrototypeOf(value);

  return prototype ? prototype.constructor.name : 'null prototype';
}

/** Calculates bytes size of input string */
function utf8Length(value) {
  // eslint-disable-next-line no-bitwise
  return ~-encodeURI(value).split(/%..|./).length;
}

/** Calculates bytes size of input object */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function jsonSize(value) {
  return utf8Length(JSON.stringify(value));
}

/**
 * Normalizes URLs in exceptions and stacktraces to a base path so Sentry can fingerprint
 * across platforms and working directory.
 *
 * @param url The URL to be normalized.
 * @param basePath The application base path.
 * @returns The normalized URL.
 */
function normalizeUrlToBase(url, basePath) {
  const escapedBase = basePath
    // Backslash to forward
    .replace(/\\/g, '/')
    // Escape RegExp special characters
    .replace(/[|\\{}()[\]^$+*?.]/g, '\\$&');

  let newUrl = url;
  try {
    newUrl = decodeURI(url);
  } catch (_Oo) {
    // Sometime this breaks
  }
  return (
    newUrl
      .replace(/\\/g, '/')
      .replace(/webpack:\/?/g, '') // Remove intermediate base path
      // eslint-disable-next-line @sentry-internal/sdk/no-regexp-constructor
      .replace(new RegExp(`(file://)?/*${escapedBase}/*`, 'ig'), 'app:///')
  );
}


//# sourceMappingURL=normalize.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/envelope.js





/**
 * Creates an envelope.
 * Make sure to always explicitly provide the generic to this function
 * so that the envelope types resolve correctly.
 */
function envelope_createEnvelope(headers, items = []) {
  return [headers, items] ;
}

/**
 * Add an item to an envelope.
 * Make sure to always explicitly provide the generic to this function
 * so that the envelope types resolve correctly.
 */
function addItemToEnvelope(envelope, newItem) {
  const [headers, items] = envelope;
  return [headers, [...items, newItem]] ;
}

/**
 * Convenience function to loop through the items and item types of an envelope.
 * (This function was mostly created because working with envelope types is painful at the moment)
 *
 * If the callback returns true, the rest of the items will be skipped.
 */
function forEachEnvelopeItem(
  envelope,
  callback,
) {
  const envelopeItems = envelope[1];

  for (const envelopeItem of envelopeItems) {
    const envelopeItemType = envelopeItem[0].type;
    const result = callback(envelopeItem, envelopeItemType);

    if (result) {
      return true;
    }
  }

  return false;
}

/**
 * Returns true if the envelope contains any of the given envelope item types
 */
function envelopeContainsItemType(envelope, types) {
  return forEachEnvelopeItem(envelope, (_, type) => types.includes(type));
}

/**
 * Encode a string to UTF8 array.
 */
function encodeUTF8(input) {
  return worldwide_GLOBAL_OBJ.__SENTRY__ && worldwide_GLOBAL_OBJ.__SENTRY__.encodePolyfill
    ? worldwide_GLOBAL_OBJ.__SENTRY__.encodePolyfill(input)
    : new TextEncoder().encode(input);
}

/**
 * Decode a UTF8 array to string.
 */
function decodeUTF8(input) {
  return GLOBAL_OBJ.__SENTRY__ && GLOBAL_OBJ.__SENTRY__.decodePolyfill
    ? GLOBAL_OBJ.__SENTRY__.decodePolyfill(input)
    : new TextDecoder().decode(input);
}

/**
 * Serializes an envelope.
 */
function serializeEnvelope(envelope) {
  const [envHeaders, items] = envelope;

  // Initially we construct our envelope as a string and only convert to binary chunks if we encounter binary data
  let parts = JSON.stringify(envHeaders);

  function append(next) {
    if (typeof parts === 'string') {
      parts = typeof next === 'string' ? parts + next : [encodeUTF8(parts), next];
    } else {
      parts.push(typeof next === 'string' ? encodeUTF8(next) : next);
    }
  }

  for (const item of items) {
    const [itemHeaders, payload] = item;

    append(`\n${JSON.stringify(itemHeaders)}\n`);

    if (typeof payload === 'string' || payload instanceof Uint8Array) {
      append(payload);
    } else {
      let stringifiedPayload;
      try {
        stringifiedPayload = JSON.stringify(payload);
      } catch (e) {
        // In case, despite all our efforts to keep `payload` circular-dependency-free, `JSON.stringify()` still
        // fails, we try again after normalizing it again with infinite normalization depth. This of course has a
        // performance impact but in this case a performance hit is better than throwing.
        stringifiedPayload = JSON.stringify(normalize(payload));
      }
      append(stringifiedPayload);
    }
  }

  return typeof parts === 'string' ? parts : concatBuffers(parts);
}

function concatBuffers(buffers) {
  const totalLength = buffers.reduce((acc, buf) => acc + buf.length, 0);

  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const buffer of buffers) {
    merged.set(buffer, offset);
    offset += buffer.length;
  }

  return merged;
}

/**
 * Parses an envelope
 */
function parseEnvelope(env) {
  let buffer = typeof env === 'string' ? encodeUTF8(env) : env;

  function readBinary(length) {
    const bin = buffer.subarray(0, length);
    // Replace the buffer with the remaining data excluding trailing newline
    buffer = buffer.subarray(length + 1);
    return bin;
  }

  function readJson() {
    let i = buffer.indexOf(0xa);
    // If we couldn't find a newline, we must have found the end of the buffer
    if (i < 0) {
      i = buffer.length;
    }

    return JSON.parse(decodeUTF8(readBinary(i))) ;
  }

  const envelopeHeader = readJson();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const items = [];

  while (buffer.length) {
    const itemHeader = readJson();
    const binaryLength = typeof itemHeader.length === 'number' ? itemHeader.length : undefined;

    items.push([itemHeader, binaryLength ? readBinary(binaryLength) : readJson()]);
  }

  return [envelopeHeader, items];
}

/**
 * Creates envelope item for a single span
 */
function envelope_createSpanEnvelopeItem(spanJson) {
  const spanHeaders = {
    type: 'span',
  };

  return [spanHeaders, spanJson];
}

/**
 * Creates attachment envelope items
 */
function createAttachmentEnvelopeItem(attachment) {
  const buffer = typeof attachment.data === 'string' ? encodeUTF8(attachment.data) : attachment.data;

  return [
    object_dropUndefinedKeys({
      type: 'attachment',
      length: buffer.length,
      filename: attachment.filename,
      content_type: attachment.contentType,
      attachment_type: attachment.attachmentType,
    }),
    buffer,
  ];
}

const ITEM_TYPE_TO_DATA_CATEGORY_MAP = {
  session: 'session',
  sessions: 'session',
  attachment: 'attachment',
  transaction: 'transaction',
  event: 'error',
  client_report: 'internal',
  user_report: 'default',
  profile: 'profile',
  profile_chunk: 'profile',
  replay_event: 'replay',
  replay_recording: 'replay',
  check_in: 'monitor',
  feedback: 'feedback',
  span: 'span',
  statsd: 'metric_bucket',
  raw_security: 'security',
};

/**
 * Maps the type of an envelope item to a data category.
 */
function envelopeItemTypeToDataCategory(type) {
  return ITEM_TYPE_TO_DATA_CATEGORY_MAP[type];
}

/** Extracts the minimal SDK info from the metadata or an events */
function getSdkMetadataForEnvelopeHeader(metadataOrEvent) {
  if (!metadataOrEvent || !metadataOrEvent.sdk) {
    return;
  }
  const { name, version } = metadataOrEvent.sdk;
  return { name, version };
}

/**
 * Creates event envelope headers, based on event, sdk info and tunnel
 * Note: This function was extracted from the core package to make it available in Replay
 */
function createEventEnvelopeHeaders(
  event,
  sdkInfo,
  tunnel,
  dsn,
) {
  const dynamicSamplingContext = event.sdkProcessingMetadata && event.sdkProcessingMetadata.dynamicSamplingContext;
  return {
    event_id: event.event_id ,
    sent_at: new Date().toISOString(),
    ...(sdkInfo && { sdk: sdkInfo }),
    ...(!!tunnel && dsn && { dsn: dsn_dsnToString(dsn) }),
    ...(dynamicSamplingContext && {
      trace: object_dropUndefinedKeys({ ...dynamicSamplingContext }),
    }),
  };
}


//# sourceMappingURL=envelope.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/envelope.js








/**
 * Apply SdkInfo (name, version, packages, integrations) to the corresponding event key.
 * Merge with existing data if any.
 **/
function enhanceEventWithSdkInfo(event, sdkInfo) {
  if (!sdkInfo) {
    return event;
  }
  event.sdk = event.sdk || {};
  event.sdk.name = event.sdk.name || sdkInfo.name;
  event.sdk.version = event.sdk.version || sdkInfo.version;
  event.sdk.integrations = [...(event.sdk.integrations || []), ...(sdkInfo.integrations || [])];
  event.sdk.packages = [...(event.sdk.packages || []), ...(sdkInfo.packages || [])];
  return event;
}

/** Creates an envelope from a Session */
function createSessionEnvelope(
  session,
  dsn,
  metadata,
  tunnel,
) {
  const sdkInfo = getSdkMetadataForEnvelopeHeader(metadata);
  const envelopeHeaders = {
    sent_at: new Date().toISOString(),
    ...(sdkInfo && { sdk: sdkInfo }),
    ...(!!tunnel && dsn && { dsn: dsn_dsnToString(dsn) }),
  };

  const envelopeItem =
    'aggregates' in session ? [{ type: 'sessions' }, session] : [{ type: 'session' }, session.toJSON()];

  return envelope_createEnvelope(envelopeHeaders, [envelopeItem]);
}

/**
 * Create an Envelope from an event.
 */
function createEventEnvelope(
  event,
  dsn,
  metadata,
  tunnel,
) {
  const sdkInfo = getSdkMetadataForEnvelopeHeader(metadata);

  /*
    Note: Due to TS, event.type may be `replay_event`, theoretically.
    In practice, we never call `createEventEnvelope` with `replay_event` type,
    and we'd have to adjust a looot of types to make this work properly.
    We want to avoid casting this around, as that could lead to bugs (e.g. when we add another type)
    So the safe choice is to really guard against the replay_event type here.
  */
  const eventType = event.type && event.type !== 'replay_event' ? event.type : 'event';

  enhanceEventWithSdkInfo(event, metadata && metadata.sdk);

  const envelopeHeaders = createEventEnvelopeHeaders(event, sdkInfo, tunnel, dsn);

  // Prevent this data (which, if it exists, was used in earlier steps in the processing pipeline) from being sent to
  // sentry. (Note: Our use of this property comes and goes with whatever we might be debugging, whatever hacks we may
  // have temporarily added, etc. Even if we don't happen to be using it at some point in the future, let's not get rid
  // of this `delete`, lest we miss putting it back in the next time the property is in use.)
  delete event.sdkProcessingMetadata;

  const eventItem = [{ type: eventType }, event];
  return envelope_createEnvelope(envelopeHeaders, [eventItem]);
}

/**
 * Create envelope from Span item.
 *
 * Takes an optional client and runs spans through `beforeSendSpan` if available.
 */
function createSpanEnvelope(spans, client) {
  function dscHasRequiredProps(dsc) {
    return !!dsc.trace_id && !!dsc.public_key;
  }

  // For the moment we'll obtain the DSC from the first span in the array
  // This might need to be changed if we permit sending multiple spans from
  // different segments in one envelope
  const dsc = getDynamicSamplingContextFromSpan(spans[0]);

  const dsn = client && client.getDsn();
  const tunnel = client && client.getOptions().tunnel;

  const headers = {
    sent_at: new Date().toISOString(),
    ...(dscHasRequiredProps(dsc) && { trace: dsc }),
    ...(!!tunnel && dsn && { dsn: dsnToString(dsn) }),
  };

  const beforeSendSpan = client && client.getOptions().beforeSendSpan;
  const convertToSpanJSON = beforeSendSpan
    ? (span) => {
        const spanJson = beforeSendSpan(spanToJSON(span) );
        if (!spanJson) {
          showSpanDropWarning();
        }
        return spanJson;
      }
    : (span) => spanToJSON(span);

  const items = [];
  for (const span of spans) {
    const spanJson = convertToSpanJSON(span);
    if (spanJson) {
      items.push(createSpanEnvelopeItem(spanJson));
    }
  }

  return createEnvelope(headers, items);
}


//# sourceMappingURL=envelope.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/constants.js
const DEFAULT_ENVIRONMENT = 'production';


//# sourceMappingURL=constants.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/semanticAttributes.js
/**
 * Use this attribute to represent the source of a span.
 * Should be one of: custom, url, route, view, component, task, unknown
 *
 */
const SEMANTIC_ATTRIBUTE_SENTRY_SOURCE = 'sentry.source';

/**
 * Use this attribute to represent the sample rate used for a span.
 */
const SEMANTIC_ATTRIBUTE_SENTRY_SAMPLE_RATE = 'sentry.sample_rate';

/**
 * Use this attribute to represent the operation of a span.
 */
const SEMANTIC_ATTRIBUTE_SENTRY_OP = 'sentry.op';

/**
 * Use this attribute to represent the origin of a span.
 */
const SEMANTIC_ATTRIBUTE_SENTRY_ORIGIN = 'sentry.origin';

/** The reason why an idle span finished. */
const SEMANTIC_ATTRIBUTE_SENTRY_IDLE_SPAN_FINISH_REASON = 'sentry.idle_span_finish_reason';

/** The unit of a measurement, which may be stored as a TimedEvent. */
const SEMANTIC_ATTRIBUTE_SENTRY_MEASUREMENT_UNIT = 'sentry.measurement_unit';

/** The value of a measurement, which may be stored as a TimedEvent. */
const SEMANTIC_ATTRIBUTE_SENTRY_MEASUREMENT_VALUE = 'sentry.measurement_value';

/**
 * The id of the profile that this span occurred in.
 */
const SEMANTIC_ATTRIBUTE_PROFILE_ID = 'sentry.profile_id';

const SEMANTIC_ATTRIBUTE_EXCLUSIVE_TIME = 'sentry.exclusive_time';

const SEMANTIC_ATTRIBUTE_CACHE_HIT = 'cache.hit';

const SEMANTIC_ATTRIBUTE_CACHE_KEY = 'cache.key';

const SEMANTIC_ATTRIBUTE_CACHE_ITEM_SIZE = 'cache.item_size';

/** TODO: Remove these once we update to latest semantic conventions */
const SEMANTIC_ATTRIBUTE_HTTP_REQUEST_METHOD = 'http.request.method';
const SEMANTIC_ATTRIBUTE_URL_FULL = 'url.full';


//# sourceMappingURL=semanticAttributes.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/baggage.js




/**
 * @deprecated Use a `"baggage"` string directly
 */
const BAGGAGE_HEADER_NAME = 'baggage';

const SENTRY_BAGGAGE_KEY_PREFIX = 'sentry-';

const SENTRY_BAGGAGE_KEY_PREFIX_REGEX = /^sentry-/;

/**
 * Max length of a serialized baggage string
 *
 * https://www.w3.org/TR/baggage/#limits
 */
const MAX_BAGGAGE_STRING_LENGTH = 8192;

/**
 * Takes a baggage header and turns it into Dynamic Sampling Context, by extracting all the "sentry-" prefixed values
 * from it.
 *
 * @param baggageHeader A very bread definition of a baggage header as it might appear in various frameworks.
 * @returns The Dynamic Sampling Context that was found on `baggageHeader`, if there was any, `undefined` otherwise.
 */
function baggageHeaderToDynamicSamplingContext(
  // Very liberal definition of what any incoming header might look like
  baggageHeader,
) {
  const baggageObject = parseBaggageHeader(baggageHeader);

  if (!baggageObject) {
    return undefined;
  }

  // Read all "sentry-" prefixed values out of the baggage object and put it onto a dynamic sampling context object.
  const dynamicSamplingContext = Object.entries(baggageObject).reduce((acc, [key, value]) => {
    if (key.match(SENTRY_BAGGAGE_KEY_PREFIX_REGEX)) {
      const nonPrefixedKey = key.slice(SENTRY_BAGGAGE_KEY_PREFIX.length);
      acc[nonPrefixedKey] = value;
    }
    return acc;
  }, {});

  // Only return a dynamic sampling context object if there are keys in it.
  // A keyless object means there were no sentry values on the header, which means that there is no DSC.
  if (Object.keys(dynamicSamplingContext).length > 0) {
    return dynamicSamplingContext ;
  } else {
    return undefined;
  }
}

/**
 * Turns a Dynamic Sampling Object into a baggage header by prefixing all the keys on the object with "sentry-".
 *
 * @param dynamicSamplingContext The Dynamic Sampling Context to turn into a header. For convenience and compatibility
 * with the `getDynamicSamplingContext` method on the Transaction class ,this argument can also be `undefined`. If it is
 * `undefined` the function will return `undefined`.
 * @returns a baggage header, created from `dynamicSamplingContext`, or `undefined` either if `dynamicSamplingContext`
 * was `undefined`, or if `dynamicSamplingContext` didn't contain any values.
 */
function baggage_dynamicSamplingContextToSentryBaggageHeader(
  // this also takes undefined for convenience and bundle size in other places
  dynamicSamplingContext,
) {
  if (!dynamicSamplingContext) {
    return undefined;
  }

  // Prefix all DSC keys with "sentry-" and put them into a new object
  const sentryPrefixedDSC = Object.entries(dynamicSamplingContext).reduce(
    (acc, [dscKey, dscValue]) => {
      if (dscValue) {
        acc[`${SENTRY_BAGGAGE_KEY_PREFIX}${dscKey}`] = dscValue;
      }
      return acc;
    },
    {},
  );

  return objectToBaggageHeader(sentryPrefixedDSC);
}

/**
 * Take a baggage header and parse it into an object.
 */
function parseBaggageHeader(
  baggageHeader,
) {
  if (!baggageHeader || (!isString(baggageHeader) && !Array.isArray(baggageHeader))) {
    return undefined;
  }

  if (Array.isArray(baggageHeader)) {
    // Combine all baggage headers into one object containing the baggage values so we can later read the Sentry-DSC-values from it
    return baggageHeader.reduce((acc, curr) => {
      const currBaggageObject = baggageHeaderToObject(curr);
      Object.entries(currBaggageObject).forEach(([key, value]) => {
        acc[key] = value;
      });
      return acc;
    }, {});
  }

  return baggageHeaderToObject(baggageHeader);
}

/**
 * Will parse a baggage header, which is a simple key-value map, into a flat object.
 *
 * @param baggageHeader The baggage header to parse.
 * @returns a flat object containing all the key-value pairs from `baggageHeader`.
 */
function baggageHeaderToObject(baggageHeader) {
  return baggageHeader
    .split(',')
    .map(baggageEntry => baggageEntry.split('=').map(keyOrValue => decodeURIComponent(keyOrValue.trim())))
    .reduce((acc, [key, value]) => {
      if (key && value) {
        acc[key] = value;
      }
      return acc;
    }, {});
}

/**
 * Turns a flat object (key-value pairs) into a baggage header, which is also just key-value pairs.
 *
 * @param object The object to turn into a baggage header.
 * @returns a baggage header string, or `undefined` if the object didn't have any values, since an empty baggage header
 * is not spec compliant.
 */
function objectToBaggageHeader(object) {
  if (Object.keys(object).length === 0) {
    // An empty baggage header is not spec compliant: We return undefined.
    return undefined;
  }

  return Object.entries(object).reduce((baggageHeader, [objectKey, objectValue], currentIndex) => {
    const baggageEntry = `${encodeURIComponent(objectKey)}=${encodeURIComponent(objectValue)}`;
    const newBaggageHeader = currentIndex === 0 ? baggageEntry : `${baggageHeader},${baggageEntry}`;
    if (newBaggageHeader.length > MAX_BAGGAGE_STRING_LENGTH) {
      DEBUG_BUILD &&
        logger.warn(
          `Not adding key: ${objectKey} with val: ${objectValue} to baggage header due to exceeding baggage size limits.`,
        );
      return baggageHeader;
    } else {
      return newBaggageHeader;
    }
  }, '');
}


//# sourceMappingURL=baggage.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/hasTracingEnabled.js


// Treeshakable guard to remove all code related to tracing

/**
 * Determines if tracing is currently enabled.
 *
 * Tracing is enabled when at least one of `tracesSampleRate` and `tracesSampler` is defined in the SDK config.
 */
function hasTracingEnabled(
  maybeOptions,
) {
  if (typeof __SENTRY_TRACING__ === 'boolean' && !__SENTRY_TRACING__) {
    return false;
  }

  const client = currentScopes_getClient();
  const options = maybeOptions || (client && client.getOptions());
  // eslint-disable-next-line deprecation/deprecation
  return !!options && (options.enableTracing || 'tracesSampleRate' in options || 'tracesSampler' in options);
}


//# sourceMappingURL=hasTracingEnabled.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/metrics/metric-summary.js


/**
 * key: bucketKey
 * value: [exportKey, MetricSummary]
 */

const METRICS_SPAN_FIELD = '_sentryMetrics';

/**
 * Fetches the metric summary if it exists for the passed span
 */
function getMetricSummaryJsonForSpan(span) {
  const storage = (span )[METRICS_SPAN_FIELD];

  if (!storage) {
    return undefined;
  }
  const output = {};

  for (const [, [exportKey, summary]] of storage) {
    const arr = output[exportKey] || (output[exportKey] = []);
    arr.push(object_dropUndefinedKeys(summary));
  }

  return output;
}

/**
 * Updates the metric summary on a span.
 */
function metric_summary_updateMetricSummaryOnSpan(
  span,
  metricType,
  sanitizedName,
  value,
  unit,
  tags,
  bucketKey,
) {
  const existingStorage = (span )[METRICS_SPAN_FIELD];
  const storage =
    existingStorage ||
    ((span )[METRICS_SPAN_FIELD] = new Map());

  const exportKey = `${metricType}:${sanitizedName}@${unit}`;
  const bucketItem = storage.get(bucketKey);

  if (bucketItem) {
    const [, summary] = bucketItem;
    storage.set(bucketKey, [
      exportKey,
      {
        min: Math.min(summary.min, value),
        max: Math.max(summary.max, value),
        count: (summary.count += 1),
        sum: (summary.sum += value),
        tags: summary.tags,
      },
    ]);
  } else {
    storage.set(bucketKey, [
      exportKey,
      {
        min: value,
        max: value,
        count: 1,
        sum: value,
        tags,
      },
    ]);
  }
}


//# sourceMappingURL=metric-summary.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/tracing/spanstatus.js
const SPAN_STATUS_UNSET = 0;
const SPAN_STATUS_OK = 1;
const SPAN_STATUS_ERROR = 2;

/**
 * Converts a HTTP status code into a sentry status with a message.
 *
 * @param httpStatus The HTTP response status code.
 * @returns The span status or unknown_error.
 */
// https://develop.sentry.dev/sdk/event-payloads/span/
function getSpanStatusFromHttpCode(httpStatus) {
  if (httpStatus < 400 && httpStatus >= 100) {
    return { code: SPAN_STATUS_OK };
  }

  if (httpStatus >= 400 && httpStatus < 500) {
    switch (httpStatus) {
      case 401:
        return { code: SPAN_STATUS_ERROR, message: 'unauthenticated' };
      case 403:
        return { code: SPAN_STATUS_ERROR, message: 'permission_denied' };
      case 404:
        return { code: SPAN_STATUS_ERROR, message: 'not_found' };
      case 409:
        return { code: SPAN_STATUS_ERROR, message: 'already_exists' };
      case 413:
        return { code: SPAN_STATUS_ERROR, message: 'failed_precondition' };
      case 429:
        return { code: SPAN_STATUS_ERROR, message: 'resource_exhausted' };
      case 499:
        return { code: SPAN_STATUS_ERROR, message: 'cancelled' };
      default:
        return { code: SPAN_STATUS_ERROR, message: 'invalid_argument' };
    }
  }

  if (httpStatus >= 500 && httpStatus < 600) {
    switch (httpStatus) {
      case 501:
        return { code: SPAN_STATUS_ERROR, message: 'unimplemented' };
      case 503:
        return { code: SPAN_STATUS_ERROR, message: 'unavailable' };
      case 504:
        return { code: SPAN_STATUS_ERROR, message: 'deadline_exceeded' };
      default:
        return { code: SPAN_STATUS_ERROR, message: 'internal_error' };
    }
  }

  return { code: SPAN_STATUS_ERROR, message: 'unknown_error' };
}

/**
 * Sets the Http status attributes on the current span based on the http code.
 * Additionally, the span's status is updated, depending on the http code.
 */
function setHttpStatus(span, httpStatus) {
  span.setAttribute('http.response.status_code', httpStatus);

  const spanStatus = getSpanStatusFromHttpCode(httpStatus);
  if (spanStatus.message !== 'unknown_error') {
    span.setStatus(spanStatus);
  }
}


//# sourceMappingURL=spanstatus.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/spanUtils.js













// These are aligned with OpenTelemetry trace flags
const TRACE_FLAG_NONE = 0x0;
const TRACE_FLAG_SAMPLED = 0x1;

// todo(v9): Remove this once we've stopped dropping spans via `beforeSendSpan`
let hasShownSpanDropWarning = false;

/**
 * Convert a span to a trace context, which can be sent as the `trace` context in an event.
 * By default, this will only include trace_id, span_id & parent_span_id.
 * If `includeAllData` is true, it will also include data, op, status & origin.
 */
function spanToTransactionTraceContext(span) {
  const { spanId: span_id, traceId: trace_id } = span.spanContext();
  const { data, op, parent_span_id, status, origin } = spanUtils_spanToJSON(span);

  return dropUndefinedKeys({
    parent_span_id,
    span_id,
    trace_id,
    data,
    op,
    status,
    origin,
  });
}

/**
 * Convert a span to a trace context, which can be sent as the `trace` context in a non-transaction event.
 */
function spanToTraceContext(span) {
  const { spanId, traceId: trace_id, isRemote } = span.spanContext();

  // If the span is remote, we use a random/virtual span as span_id to the trace context,
  // and the remote span as parent_span_id
  const parent_span_id = isRemote ? spanId : spanUtils_spanToJSON(span).parent_span_id;
  const span_id = isRemote ? generateSpanId() : spanId;

  return object_dropUndefinedKeys({
    parent_span_id,
    span_id,
    trace_id,
  });
}

/**
 * Convert a Span to a Sentry trace header.
 */
function spanToTraceHeader(span) {
  const { traceId, spanId } = span.spanContext();
  const sampled = spanIsSampled(span);
  return generateSentryTraceHeader(traceId, spanId, sampled);
}

/**
 * Convert a span time input into a timestamp in seconds.
 */
function spanTimeInputToSeconds(input) {
  if (typeof input === 'number') {
    return ensureTimestampInSeconds(input);
  }

  if (Array.isArray(input)) {
    // See {@link HrTime} for the array-based time format
    return input[0] + input[1] / 1e9;
  }

  if (input instanceof Date) {
    return ensureTimestampInSeconds(input.getTime());
  }

  return time_timestampInSeconds();
}

/**
 * Converts a timestamp to second, if it was in milliseconds, or keeps it as second.
 */
function ensureTimestampInSeconds(timestamp) {
  const isMs = timestamp > 9999999999;
  return isMs ? timestamp / 1000 : timestamp;
}

/**
 * Convert a span to a JSON representation.
 */
// Note: Because of this, we currently have a circular type dependency (which we opted out of in package.json).
// This is not avoidable as we need `spanToJSON` in `spanUtils.ts`, which in turn is needed by `span.ts` for backwards compatibility.
// And `spanToJSON` needs the Span class from `span.ts` to check here.
function spanUtils_spanToJSON(span) {
  if (spanIsSentrySpan(span)) {
    return span.getSpanJSON();
  }

  try {
    const { spanId: span_id, traceId: trace_id } = span.spanContext();

    // Handle a span from @opentelemetry/sdk-base-trace's `Span` class
    if (spanIsOpenTelemetrySdkTraceBaseSpan(span)) {
      const { attributes, startTime, name, endTime, parentSpanId, status } = span;

      return object_dropUndefinedKeys({
        span_id,
        trace_id,
        data: attributes,
        description: name,
        parent_span_id: parentSpanId,
        start_timestamp: spanTimeInputToSeconds(startTime),
        // This is [0,0] by default in OTEL, in which case we want to interpret this as no end time
        timestamp: spanTimeInputToSeconds(endTime) || undefined,
        status: getStatusMessage(status),
        op: attributes[SEMANTIC_ATTRIBUTE_SENTRY_OP],
        origin: attributes[SEMANTIC_ATTRIBUTE_SENTRY_ORIGIN] ,
        _metrics_summary: getMetricSummaryJsonForSpan(span),
      });
    }

    // Finally, at least we have `spanContext()`....
    return {
      span_id,
      trace_id,
    };
  } catch (e) {
    return {};
  }
}

function spanIsOpenTelemetrySdkTraceBaseSpan(span) {
  const castSpan = span ;
  return !!castSpan.attributes && !!castSpan.startTime && !!castSpan.name && !!castSpan.endTime && !!castSpan.status;
}

/** Exported only for tests. */

/**
 * Sadly, due to circular dependency checks we cannot actually import the Span class here and check for instanceof.
 * :( So instead we approximate this by checking if it has the `getSpanJSON` method.
 */
function spanIsSentrySpan(span) {
  return typeof (span ).getSpanJSON === 'function';
}

/**
 * Returns true if a span is sampled.
 * In most cases, you should just use `span.isRecording()` instead.
 * However, this has a slightly different semantic, as it also returns false if the span is finished.
 * So in the case where this distinction is important, use this method.
 */
function spanIsSampled(span) {
  // We align our trace flags with the ones OpenTelemetry use
  // So we also check for sampled the same way they do.
  const { traceFlags } = span.spanContext();
  return traceFlags === TRACE_FLAG_SAMPLED;
}

/** Get the status message to use for a JSON representation of a span. */
function getStatusMessage(status) {
  if (!status || status.code === SPAN_STATUS_UNSET) {
    return undefined;
  }

  if (status.code === SPAN_STATUS_OK) {
    return 'ok';
  }

  return status.message || 'unknown_error';
}

const CHILD_SPANS_FIELD = '_sentryChildSpans';
const ROOT_SPAN_FIELD = '_sentryRootSpan';

/**
 * Adds an opaque child span reference to a span.
 */
function addChildSpanToSpan(span, childSpan) {
  // We store the root span reference on the child span
  // We need this for `getRootSpan()` to work
  const rootSpan = span[ROOT_SPAN_FIELD] || span;
  addNonEnumerableProperty(childSpan , ROOT_SPAN_FIELD, rootSpan);

  // We store a list of child spans on the parent span
  // We need this for `getSpanDescendants()` to work
  if (span[CHILD_SPANS_FIELD]) {
    span[CHILD_SPANS_FIELD].add(childSpan);
  } else {
    addNonEnumerableProperty(span, CHILD_SPANS_FIELD, new Set([childSpan]));
  }
}

/** This is only used internally by Idle Spans. */
function removeChildSpanFromSpan(span, childSpan) {
  if (span[CHILD_SPANS_FIELD]) {
    span[CHILD_SPANS_FIELD].delete(childSpan);
  }
}

/**
 * Returns an array of the given span and all of its descendants.
 */
function getSpanDescendants(span) {
  const resultSet = new Set();

  function addSpanChildren(span) {
    // This exit condition is required to not infinitely loop in case of a circular dependency.
    if (resultSet.has(span)) {
      return;
      // We want to ignore unsampled spans (e.g. non recording spans)
    } else if (spanIsSampled(span)) {
      resultSet.add(span);
      const childSpans = span[CHILD_SPANS_FIELD] ? Array.from(span[CHILD_SPANS_FIELD]) : [];
      for (const childSpan of childSpans) {
        addSpanChildren(childSpan);
      }
    }
  }

  addSpanChildren(span);

  return Array.from(resultSet);
}

/**
 * Returns the root span of a given span.
 */
function getRootSpan(span) {
  return span[ROOT_SPAN_FIELD] || span;
}

/**
 * Returns the currently active span.
 */
function getActiveSpan() {
  const carrier = getMainCarrier();
  const acs = getAsyncContextStrategy(carrier);
  if (acs.getActiveSpan) {
    return acs.getActiveSpan();
  }

  return _getSpanForScope(getCurrentScope());
}

/**
 * Updates the metric summary on the currently active span
 */
function updateMetricSummaryOnActiveSpan(
  metricType,
  sanitizedName,
  value,
  unit,
  tags,
  bucketKey,
) {
  const span = getActiveSpan();
  if (span) {
    updateMetricSummaryOnSpan(span, metricType, sanitizedName, value, unit, tags, bucketKey);
  }
}

/**
 * Logs a warning once if `beforeSendSpan` is used to drop spans.
 *
 * todo(v9): Remove this once we've stopped dropping spans via `beforeSendSpan`.
 */
function spanUtils_showSpanDropWarning() {
  if (!hasShownSpanDropWarning) {
    consoleSandbox(() => {
      // eslint-disable-next-line no-console
      console.warn(
        '[Sentry] Deprecation warning: Returning null from `beforeSendSpan` will be disallowed from SDK version 9.0.0 onwards. The callback will only support mutating spans. To drop certain spans, configure the respective integrations directly.',
      );
    });
    hasShownSpanDropWarning = true;
  }
}


//# sourceMappingURL=spanUtils.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/tracing/dynamicSamplingContext.js








/**
 * If you change this value, also update the terser plugin config to
 * avoid minification of the object property!
 */
const FROZEN_DSC_FIELD = '_frozenDsc';

/**
 * Freeze the given DSC on the given span.
 */
function freezeDscOnSpan(span, dsc) {
  const spanWithMaybeDsc = span ;
  addNonEnumerableProperty(spanWithMaybeDsc, FROZEN_DSC_FIELD, dsc);
}

/**
 * Creates a dynamic sampling context from a client.
 *
 * Dispatches the `createDsc` lifecycle hook as a side effect.
 */
function getDynamicSamplingContextFromClient(trace_id, client) {
  const options = client.getOptions();

  const { publicKey: public_key } = client.getDsn() || {};

  const dsc = object_dropUndefinedKeys({
    environment: options.environment || DEFAULT_ENVIRONMENT,
    release: options.release,
    public_key,
    trace_id,
  }) ;

  client.emit('createDsc', dsc);

  return dsc;
}

/**
 * Get the dynamic sampling context for the currently active scopes.
 */
function getDynamicSamplingContextFromScope(client, scope) {
  const propagationContext = scope.getPropagationContext();
  return propagationContext.dsc || getDynamicSamplingContextFromClient(propagationContext.traceId, client);
}

/**
 * Creates a dynamic sampling context from a span (and client and scope)
 *
 * @param span the span from which a few values like the root span name and sample rate are extracted.
 *
 * @returns a dynamic sampling context
 */
function dynamicSamplingContext_getDynamicSamplingContextFromSpan(span) {
  const client = currentScopes_getClient();
  if (!client) {
    return {};
  }

  const rootSpan = getRootSpan(span);

  // For core implementation, we freeze the DSC onto the span as a non-enumerable property
  const frozenDsc = (rootSpan )[FROZEN_DSC_FIELD];
  if (frozenDsc) {
    return frozenDsc;
  }

  // For OpenTelemetry, we freeze the DSC on the trace state
  const traceState = rootSpan.spanContext().traceState;
  const traceStateDsc = traceState && traceState.get('sentry.dsc');

  // If the span has a DSC, we want it to take precedence
  const dscOnTraceState = traceStateDsc && baggageHeaderToDynamicSamplingContext(traceStateDsc);

  if (dscOnTraceState) {
    return dscOnTraceState;
  }

  // Else, we generate it from the span
  const dsc = getDynamicSamplingContextFromClient(span.spanContext().traceId, client);
  const jsonSpan = spanUtils_spanToJSON(rootSpan);
  const attributes = jsonSpan.data || {};
  const maybeSampleRate = attributes[SEMANTIC_ATTRIBUTE_SENTRY_SAMPLE_RATE];

  if (maybeSampleRate != null) {
    dsc.sample_rate = `${maybeSampleRate}`;
  }

  // We don't want to have a transaction name in the DSC if the source is "url" because URLs might contain PII
  const source = attributes[SEMANTIC_ATTRIBUTE_SENTRY_SOURCE];

  // after JSON conversion, txn.name becomes jsonSpan.description
  const name = jsonSpan.description;
  if (source !== 'url' && name) {
    dsc.transaction = name;
  }

  // How can we even land here with hasTracingEnabled() returning false?
  // Otel creates a Non-recording span in Tracing Without Performance mode when handling incoming requests
  // So we end up with an active span that is not sampled (neither positively nor negatively)
  if (hasTracingEnabled()) {
    dsc.sampled = String(spanIsSampled(rootSpan));
  }

  client.emit('createDsc', dsc, rootSpan);

  return dsc;
}

/**
 * Convert a Span to a baggage header.
 */
function spanToBaggageHeader(span) {
  const dsc = dynamicSamplingContext_getDynamicSamplingContextFromSpan(span);
  return dynamicSamplingContextToSentryBaggageHeader(dsc);
}


//# sourceMappingURL=dynamicSamplingContext.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/clientreport.js



/**
 * Creates client report envelope
 * @param discarded_events An array of discard events
 * @param dsn A DSN that can be set on the header. Optional.
 */
function createClientReportEnvelope(
  discarded_events,
  dsn,
  timestamp,
) {
  const clientReportItem = [
    { type: 'client_report' },
    {
      timestamp: timestamp || dateTimestampInSeconds(),
      discarded_events,
    },
  ];
  return envelope_createEnvelope(dsn ? { dsn } : {}, [clientReportItem]);
}


//# sourceMappingURL=clientreport.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/error.js
/** An error emitted by Sentry SDKs and related utilities. */
class SentryError extends Error {
  /** Display name of this error instance. */

   constructor(
     message,
    logLevel = 'warn',
  ) {
    super(message);this.message = message;
    this.name = new.target.prototype.constructor.name;
    // This sets the prototype to be `Error`, not `SentryError`. It's unclear why we do this, but commenting this line
    // out causes various (seemingly totally unrelated) playwright tests consistently time out. FYI, this makes
    // instances of `SentryError` fail `obj instanceof SentryError` checks.
    Object.setPrototypeOf(this, new.target.prototype);
    this.logLevel = logLevel;
  }
}


//# sourceMappingURL=error.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/syncpromise.js


/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/no-explicit-any */

/** SyncPromise internal states */
var States; (function (States) {
  /** Pending */
  const PENDING = 0; States[States["PENDING"] = PENDING] = "PENDING";
  /** Resolved / OK */
  const RESOLVED = 1; States[States["RESOLVED"] = RESOLVED] = "RESOLVED";
  /** Rejected / Error */
  const REJECTED = 2; States[States["REJECTED"] = REJECTED] = "REJECTED";
})(States || (States = {}));

// Overloads so we can call resolvedSyncPromise without arguments and generic argument

/**
 * Creates a resolved sync promise.
 *
 * @param value the value to resolve the promise with
 * @returns the resolved sync promise
 */
function resolvedSyncPromise(value) {
  return new SyncPromise(resolve => {
    resolve(value);
  });
}

/**
 * Creates a rejected sync promise.
 *
 * @param value the value to reject the promise with
 * @returns the rejected sync promise
 */
function rejectedSyncPromise(reason) {
  return new SyncPromise((_, reject) => {
    reject(reason);
  });
}

/**
 * Thenable class that behaves like a Promise and follows it's interface
 * but is not async internally
 */
class SyncPromise {

   constructor(
    executor,
  ) {SyncPromise.prototype.__init.call(this);SyncPromise.prototype.__init2.call(this);SyncPromise.prototype.__init3.call(this);SyncPromise.prototype.__init4.call(this);
    this._state = States.PENDING;
    this._handlers = [];

    try {
      executor(this._resolve, this._reject);
    } catch (e) {
      this._reject(e);
    }
  }

  /** JSDoc */
   then(
    onfulfilled,
    onrejected,
  ) {
    return new SyncPromise((resolve, reject) => {
      this._handlers.push([
        false,
        result => {
          if (!onfulfilled) {
            // TODO: ¯\_(ツ)_/¯
            // TODO: FIXME
            resolve(result );
          } else {
            try {
              resolve(onfulfilled(result));
            } catch (e) {
              reject(e);
            }
          }
        },
        reason => {
          if (!onrejected) {
            reject(reason);
          } else {
            try {
              resolve(onrejected(reason));
            } catch (e) {
              reject(e);
            }
          }
        },
      ]);
      this._executeHandlers();
    });
  }

  /** JSDoc */
   catch(
    onrejected,
  ) {
    return this.then(val => val, onrejected);
  }

  /** JSDoc */
   finally(onfinally) {
    return new SyncPromise((resolve, reject) => {
      let val;
      let isRejected;

      return this.then(
        value => {
          isRejected = false;
          val = value;
          if (onfinally) {
            onfinally();
          }
        },
        reason => {
          isRejected = true;
          val = reason;
          if (onfinally) {
            onfinally();
          }
        },
      ).then(() => {
        if (isRejected) {
          reject(val);
          return;
        }

        resolve(val );
      });
    });
  }

  /** JSDoc */
    __init() {this._resolve = (value) => {
    this._setResult(States.RESOLVED, value);
  };}

  /** JSDoc */
    __init2() {this._reject = (reason) => {
    this._setResult(States.REJECTED, reason);
  };}

  /** JSDoc */
    __init3() {this._setResult = (state, value) => {
    if (this._state !== States.PENDING) {
      return;
    }

    if (is_isThenable(value)) {
      void (value ).then(this._resolve, this._reject);
      return;
    }

    this._state = state;
    this._value = value;

    this._executeHandlers();
  };}

  /** JSDoc */
    __init4() {this._executeHandlers = () => {
    if (this._state === States.PENDING) {
      return;
    }

    const cachedHandlers = this._handlers.slice();
    this._handlers = [];

    cachedHandlers.forEach(handler => {
      if (handler[0]) {
        return;
      }

      if (this._state === States.RESOLVED) {
        handler[1](this._value );
      }

      if (this._state === States.REJECTED) {
        handler[2](this._value);
      }

      handler[0] = true;
    });
  };}
}


//# sourceMappingURL=syncpromise.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/parseSampleRate.js



/**
 * Parse a sample rate from a given value.
 * This will either return a boolean or number sample rate, if the sample rate is valid (between 0 and 1).
 * If a string is passed, we try to convert it to a number.
 *
 * Any invalid sample rate will return `undefined`.
 */
function parseSampleRate(sampleRate) {
  if (typeof sampleRate === 'boolean') {
    return Number(sampleRate);
  }

  const rate = typeof sampleRate === 'string' ? parseFloat(sampleRate) : sampleRate;
  if (typeof rate !== 'number' || isNaN(rate) || rate < 0 || rate > 1) {
    debug_build_DEBUG_BUILD &&
      logger_logger.warn(
        `[Tracing] Given sample rate is invalid. Sample rate must be a boolean or a number between 0 and 1. Got ${JSON.stringify(
          sampleRate,
        )} of type ${JSON.stringify(typeof sampleRate)}.`,
      );
    return undefined;
  }

  return rate;
}


//# sourceMappingURL=parseSampleRate.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/eventProcessors.js





/**
 * Process an array of event processors, returning the processed event (or `null` if the event was dropped).
 */
function notifyEventProcessors(
  processors,
  event,
  hint,
  index = 0,
) {
  return new SyncPromise((resolve, reject) => {
    const processor = processors[index];
    if (event === null || typeof processor !== 'function') {
      resolve(event);
    } else {
      const result = processor({ ...event }, hint) ;

      debug_build_DEBUG_BUILD && processor.id && result === null && logger_logger.log(`Event processor "${processor.id}" dropped event`);

      if (is_isThenable(result)) {
        void result
          .then(final => notifyEventProcessors(processors, final, hint, index + 1).then(resolve))
          .then(null, reject);
      } else {
        void notifyEventProcessors(processors, result, hint, index + 1)
          .then(resolve)
          .then(null, reject);
      }
    }
  });
}


//# sourceMappingURL=eventProcessors.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/debug-ids.js


let parsedStackResults;
let lastKeysCount;
let cachedFilenameDebugIds;

/**
 * Returns a map of filenames to debug identifiers.
 */
function getFilenameToDebugIdMap(stackParser) {
  const debugIdMap = worldwide_GLOBAL_OBJ._sentryDebugIds;
  if (!debugIdMap) {
    return {};
  }

  const debugIdKeys = Object.keys(debugIdMap);

  // If the count of registered globals hasn't changed since the last call, we
  // can just return the cached result.
  if (cachedFilenameDebugIds && debugIdKeys.length === lastKeysCount) {
    return cachedFilenameDebugIds;
  }

  lastKeysCount = debugIdKeys.length;

  // Build a map of filename -> debug_id.
  cachedFilenameDebugIds = debugIdKeys.reduce((acc, stackKey) => {
    if (!parsedStackResults) {
      parsedStackResults = {};
    }

    const result = parsedStackResults[stackKey];

    if (result) {
      acc[result[0]] = result[1];
    } else {
      const parsedStack = stackParser(stackKey);

      for (let i = parsedStack.length - 1; i >= 0; i--) {
        const stackFrame = parsedStack[i];
        const filename = stackFrame && stackFrame.filename;
        const debugId = debugIdMap[stackKey];

        if (filename && debugId) {
          acc[filename] = debugId;
          parsedStackResults[stackKey] = [filename, debugId];
          break;
        }
      }
    }

    return acc;
  }, {});

  return cachedFilenameDebugIds;
}

/**
 * Returns a list of debug images for the given resources.
 */
function getDebugImagesForResources(
  stackParser,
  resource_paths,
) {
  const filenameDebugIdMap = getFilenameToDebugIdMap(stackParser);

  if (!filenameDebugIdMap) {
    return [];
  }

  const images = [];
  for (const path of resource_paths) {
    if (path && filenameDebugIdMap[path]) {
      images.push({
        type: 'sourcemap',
        code_file: path,
        debug_id: filenameDebugIdMap[path] ,
      });
    }
  }

  return images;
}


//# sourceMappingURL=debug-ids.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/applyScopeDataToEvent.js





/**
 * Applies data from the scope to the event and runs all event processors on it.
 */
function applyScopeDataToEvent(event, data) {
  const { fingerprint, span, breadcrumbs, sdkProcessingMetadata } = data;

  // Apply general data
  applyDataToEvent(event, data);

  // We want to set the trace context for normal events only if there isn't already
  // a trace context on the event. There is a product feature in place where we link
  // errors with transaction and it relies on that.
  if (span) {
    applySpanToEvent(event, span);
  }

  applyFingerprintToEvent(event, fingerprint);
  applyBreadcrumbsToEvent(event, breadcrumbs);
  applySdkMetadataToEvent(event, sdkProcessingMetadata);
}

/** Merge data of two scopes together. */
function mergeScopeData(data, mergeData) {
  const {
    extra,
    tags,
    user,
    contexts,
    level,
    sdkProcessingMetadata,
    breadcrumbs,
    fingerprint,
    eventProcessors,
    attachments,
    propagationContext,
    transactionName,
    span,
  } = mergeData;

  mergeAndOverwriteScopeData(data, 'extra', extra);
  mergeAndOverwriteScopeData(data, 'tags', tags);
  mergeAndOverwriteScopeData(data, 'user', user);
  mergeAndOverwriteScopeData(data, 'contexts', contexts);

  data.sdkProcessingMetadata = merge(data.sdkProcessingMetadata, sdkProcessingMetadata, 2);

  if (level) {
    data.level = level;
  }

  if (transactionName) {
    data.transactionName = transactionName;
  }

  if (span) {
    data.span = span;
  }

  if (breadcrumbs.length) {
    data.breadcrumbs = [...data.breadcrumbs, ...breadcrumbs];
  }

  if (fingerprint.length) {
    data.fingerprint = [...data.fingerprint, ...fingerprint];
  }

  if (eventProcessors.length) {
    data.eventProcessors = [...data.eventProcessors, ...eventProcessors];
  }

  if (attachments.length) {
    data.attachments = [...data.attachments, ...attachments];
  }

  data.propagationContext = { ...data.propagationContext, ...propagationContext };
}

/**
 * Merges certain scope data. Undefined values will overwrite any existing values.
 * Exported only for tests.
 */
function mergeAndOverwriteScopeData

(data, prop, mergeVal) {
  data[prop] = merge(data[prop], mergeVal, 1);
}

function applyDataToEvent(event, data) {
  const { extra, tags, user, contexts, level, transactionName } = data;

  const cleanedExtra = object_dropUndefinedKeys(extra);
  if (cleanedExtra && Object.keys(cleanedExtra).length) {
    event.extra = { ...cleanedExtra, ...event.extra };
  }

  const cleanedTags = object_dropUndefinedKeys(tags);
  if (cleanedTags && Object.keys(cleanedTags).length) {
    event.tags = { ...cleanedTags, ...event.tags };
  }

  const cleanedUser = object_dropUndefinedKeys(user);
  if (cleanedUser && Object.keys(cleanedUser).length) {
    event.user = { ...cleanedUser, ...event.user };
  }

  const cleanedContexts = object_dropUndefinedKeys(contexts);
  if (cleanedContexts && Object.keys(cleanedContexts).length) {
    event.contexts = { ...cleanedContexts, ...event.contexts };
  }

  if (level) {
    event.level = level;
  }

  // transaction events get their `transaction` from the root span name
  if (transactionName && event.type !== 'transaction') {
    event.transaction = transactionName;
  }
}

function applyBreadcrumbsToEvent(event, breadcrumbs) {
  const mergedBreadcrumbs = [...(event.breadcrumbs || []), ...breadcrumbs];
  event.breadcrumbs = mergedBreadcrumbs.length ? mergedBreadcrumbs : undefined;
}

function applySdkMetadataToEvent(event, sdkProcessingMetadata) {
  event.sdkProcessingMetadata = {
    ...event.sdkProcessingMetadata,
    ...sdkProcessingMetadata,
  };
}

function applySpanToEvent(event, span) {
  event.contexts = {
    trace: spanToTraceContext(span),
    ...event.contexts,
  };

  event.sdkProcessingMetadata = {
    dynamicSamplingContext: dynamicSamplingContext_getDynamicSamplingContextFromSpan(span),
    ...event.sdkProcessingMetadata,
  };

  const rootSpan = getRootSpan(span);
  const transactionName = spanUtils_spanToJSON(rootSpan).description;
  if (transactionName && !event.transaction && event.type === 'transaction') {
    event.transaction = transactionName;
  }
}

/**
 * Applies fingerprint from the scope to the event if there's one,
 * uses message if there's one instead or get rid of empty fingerprint
 */
function applyFingerprintToEvent(event, fingerprint) {
  // Make sure it's an array first and we actually have something in place
  event.fingerprint = event.fingerprint
    ? Array.isArray(event.fingerprint)
      ? event.fingerprint
      : [event.fingerprint]
    : [];

  // If we have something on the scope, then merge it with event
  if (fingerprint) {
    event.fingerprint = event.fingerprint.concat(fingerprint);
  }

  // If we have no data at all, remove empty array default
  if (event.fingerprint && !event.fingerprint.length) {
    delete event.fingerprint;
  }
}


//# sourceMappingURL=applyScopeDataToEvent.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/prepareEvent.js











/**
 * This type makes sure that we get either a CaptureContext, OR an EventHint.
 * It does not allow mixing them, which could lead to unexpected outcomes, e.g. this is disallowed:
 * { user: { id: '123' }, mechanism: { handled: false } }
 */

/**
 * Adds common information to events.
 *
 * The information includes release and environment from `options`,
 * breadcrumbs and context (extra, tags and user) from the scope.
 *
 * Information that is already present in the event is never overwritten. For
 * nested objects, such as the context, keys are merged.
 *
 * @param event The original event.
 * @param hint May contain additional information about the original exception.
 * @param scope A scope containing event metadata.
 * @returns A new event with more information.
 * @hidden
 */
function prepareEvent(
  options,
  event,
  hint,
  scope,
  client,
  isolationScope,
) {
  const { normalizeDepth = 3, normalizeMaxBreadth = 1000 } = options;
  const prepared = {
    ...event,
    event_id: event.event_id || hint.event_id || misc_uuid4(),
    timestamp: event.timestamp || dateTimestampInSeconds(),
  };
  const integrations = hint.integrations || options.integrations.map(i => i.name);

  applyClientOptions(prepared, options);
  applyIntegrationsMetadata(prepared, integrations);

  if (client) {
    client.emit('applyFrameMetadata', event);
  }

  // Only put debug IDs onto frames for error events.
  if (event.type === undefined) {
    applyDebugIds(prepared, options.stackParser);
  }

  // If we have scope given to us, use it as the base for further modifications.
  // This allows us to prevent unnecessary copying of data if `captureContext` is not provided.
  const finalScope = getFinalScope(scope, hint.captureContext);

  if (hint.mechanism) {
    addExceptionMechanism(prepared, hint.mechanism);
  }

  const clientEventProcessors = client ? client.getEventProcessors() : [];

  // This should be the last thing called, since we want that
  // {@link Scope.addEventProcessor} gets the finished prepared event.
  // Merge scope data together
  const data = getGlobalScope().getScopeData();

  if (isolationScope) {
    const isolationData = isolationScope.getScopeData();
    mergeScopeData(data, isolationData);
  }

  if (finalScope) {
    const finalScopeData = finalScope.getScopeData();
    mergeScopeData(data, finalScopeData);
  }

  const attachments = [...(hint.attachments || []), ...data.attachments];
  if (attachments.length) {
    hint.attachments = attachments;
  }

  applyScopeDataToEvent(prepared, data);

  const eventProcessors = [
    ...clientEventProcessors,
    // Run scope event processors _after_ all other processors
    ...data.eventProcessors,
  ];

  const result = notifyEventProcessors(eventProcessors, prepared, hint);

  return result.then(evt => {
    if (evt) {
      // We apply the debug_meta field only after all event processors have ran, so that if any event processors modified
      // file names (e.g.the RewriteFrames integration) the filename -> debug ID relationship isn't destroyed.
      // This should not cause any PII issues, since we're only moving data that is already on the event and not adding
      // any new data
      applyDebugMeta(evt);
    }

    if (typeof normalizeDepth === 'number' && normalizeDepth > 0) {
      return normalizeEvent(evt, normalizeDepth, normalizeMaxBreadth);
    }
    return evt;
  });
}

/**
 * Enhances event using the client configuration.
 * It takes care of all "static" values like environment, release and `dist`,
 * as well as truncating overly long values.
 *
 * Only exported for tests.
 *
 * @param event event instance to be enhanced
 */
function applyClientOptions(event, options) {
  const { environment, release, dist, maxValueLength = 250 } = options;

  // empty strings do not make sense for environment, release, and dist
  // so we handle them the same as if they were not provided
  event.environment = event.environment || environment || DEFAULT_ENVIRONMENT;

  if (!event.release && release) {
    event.release = release;
  }

  if (!event.dist && dist) {
    event.dist = dist;
  }

  if (event.message) {
    event.message = truncate(event.message, maxValueLength);
  }

  const exception = event.exception && event.exception.values && event.exception.values[0];
  if (exception && exception.value) {
    exception.value = truncate(exception.value, maxValueLength);
  }

  const request = event.request;
  if (request && request.url) {
    request.url = truncate(request.url, maxValueLength);
  }
}

/**
 * Puts debug IDs into the stack frames of an error event.
 */
function applyDebugIds(event, stackParser) {
  // Build a map of filename -> debug_id
  const filenameDebugIdMap = getFilenameToDebugIdMap(stackParser);

  try {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    event.exception.values.forEach(exception => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      exception.stacktrace.frames.forEach(frame => {
        if (filenameDebugIdMap && frame.filename) {
          frame.debug_id = filenameDebugIdMap[frame.filename];
        }
      });
    });
  } catch (e) {
    // To save bundle size we're just try catching here instead of checking for the existence of all the different objects.
  }
}

/**
 * Moves debug IDs from the stack frames of an error event into the debug_meta field.
 */
function applyDebugMeta(event) {
  // Extract debug IDs and filenames from the stack frames on the event.
  const filenameDebugIdMap = {};
  try {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    event.exception.values.forEach(exception => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      exception.stacktrace.frames.forEach(frame => {
        if (frame.debug_id) {
          if (frame.abs_path) {
            filenameDebugIdMap[frame.abs_path] = frame.debug_id;
          } else if (frame.filename) {
            filenameDebugIdMap[frame.filename] = frame.debug_id;
          }
          delete frame.debug_id;
        }
      });
    });
  } catch (e) {
    // To save bundle size we're just try catching here instead of checking for the existence of all the different objects.
  }

  if (Object.keys(filenameDebugIdMap).length === 0) {
    return;
  }

  // Fill debug_meta information
  event.debug_meta = event.debug_meta || {};
  event.debug_meta.images = event.debug_meta.images || [];
  const images = event.debug_meta.images;
  Object.entries(filenameDebugIdMap).forEach(([filename, debug_id]) => {
    images.push({
      type: 'sourcemap',
      code_file: filename,
      debug_id,
    });
  });
}

/**
 * This function adds all used integrations to the SDK info in the event.
 * @param event The event that will be filled with all integrations.
 */
function applyIntegrationsMetadata(event, integrationNames) {
  if (integrationNames.length > 0) {
    event.sdk = event.sdk || {};
    event.sdk.integrations = [...(event.sdk.integrations || []), ...integrationNames];
  }
}

/**
 * Applies `normalize` function on necessary `Event` attributes to make them safe for serialization.
 * Normalized keys:
 * - `breadcrumbs.data`
 * - `user`
 * - `contexts`
 * - `extra`
 * @param event Event
 * @returns Normalized event
 */
function normalizeEvent(event, depth, maxBreadth) {
  if (!event) {
    return null;
  }

  const normalized = {
    ...event,
    ...(event.breadcrumbs && {
      breadcrumbs: event.breadcrumbs.map(b => ({
        ...b,
        ...(b.data && {
          data: normalize(b.data, depth, maxBreadth),
        }),
      })),
    }),
    ...(event.user && {
      user: normalize(event.user, depth, maxBreadth),
    }),
    ...(event.contexts && {
      contexts: normalize(event.contexts, depth, maxBreadth),
    }),
    ...(event.extra && {
      extra: normalize(event.extra, depth, maxBreadth),
    }),
  };

  // event.contexts.trace stores information about a Transaction. Similarly,
  // event.spans[] stores information about child Spans. Given that a
  // Transaction is conceptually a Span, normalization should apply to both
  // Transactions and Spans consistently.
  // For now the decision is to skip normalization of Transactions and Spans,
  // so this block overwrites the normalized event to add back the original
  // Transaction information prior to normalization.
  if (event.contexts && event.contexts.trace && normalized.contexts) {
    normalized.contexts.trace = event.contexts.trace;

    // event.contexts.trace.data may contain circular/dangerous data so we need to normalize it
    if (event.contexts.trace.data) {
      normalized.contexts.trace.data = normalize(event.contexts.trace.data, depth, maxBreadth);
    }
  }

  // event.spans[].data may contain circular/dangerous data so we need to normalize it
  if (event.spans) {
    normalized.spans = event.spans.map(span => {
      return {
        ...span,
        ...(span.data && {
          data: normalize(span.data, depth, maxBreadth),
        }),
      };
    });
  }

  // event.contexts.flags (FeatureFlagContext) stores context for our feature
  // flag integrations. It has a greater nesting depth than our other typed
  // Contexts, so we re-normalize with a fixed depth of 3 here. We do not want
  // to skip this in case of conflicting, user-provided context.
  if (event.contexts && event.contexts.flags && normalized.contexts) {
    normalized.contexts.flags = normalize(event.contexts.flags, 3, maxBreadth);
  }

  return normalized;
}

function getFinalScope(
  scope,
  captureContext,
) {
  if (!captureContext) {
    return scope;
  }

  const finalScope = scope ? scope.clone() : new Scope();
  finalScope.update(captureContext);
  return finalScope;
}

/**
 * Parse either an `EventHint` directly, or convert a `CaptureContext` to an `EventHint`.
 * This is used to allow to update method signatures that used to accept a `CaptureContext` but should now accept an `EventHint`.
 */
function parseEventHintOrCaptureContext(
  hint,
) {
  if (!hint) {
    return undefined;
  }

  // If you pass a Scope or `() => Scope` as CaptureContext, we just return this as captureContext
  if (hintIsScopeOrFunction(hint)) {
    return { captureContext: hint };
  }

  if (hintIsScopeContext(hint)) {
    return {
      captureContext: hint,
    };
  }

  return hint;
}

function hintIsScopeOrFunction(
  hint,
) {
  return hint instanceof Scope || typeof hint === 'function';
}

const captureContextKeys = [
  'user',
  'level',
  'extra',
  'contexts',
  'tags',
  'fingerprint',
  'requestSession',
  'propagationContext',
] ;

function hintIsScopeContext(hint) {
  return Object.keys(hint).some(key => captureContextKeys.includes(key ));
}


//# sourceMappingURL=prepareEvent.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/baseclient.js



















const ALREADY_SEEN_ERROR = "Not capturing exception because it's already been captured.";

/**
 * Base implementation for all JavaScript SDK clients.
 *
 * Call the constructor with the corresponding options
 * specific to the client subclass. To access these options later, use
 * {@link Client.getOptions}.
 *
 * If a Dsn is specified in the options, it will be parsed and stored. Use
 * {@link Client.getDsn} to retrieve the Dsn at any moment. In case the Dsn is
 * invalid, the constructor will throw a {@link SentryException}. Note that
 * without a valid Dsn, the SDK will not send any events to Sentry.
 *
 * Before sending an event, it is passed through
 * {@link BaseClient._prepareEvent} to add SDK information and scope data
 * (breadcrumbs and context). To add more custom information, override this
 * method and extend the resulting prepared event.
 *
 * To issue automatically created events (e.g. via instrumentation), use
 * {@link Client.captureEvent}. It will prepare the event and pass it through
 * the callback lifecycle. To issue auto-breadcrumbs, use
 * {@link Client.addBreadcrumb}.
 *
 * @example
 * class NodeClient extends BaseClient<NodeOptions> {
 *   public constructor(options: NodeOptions) {
 *     super(options);
 *   }
 *
 *   // ...
 * }
 */
class BaseClient {
  /** Options passed to the SDK. */

  /** The client Dsn, if specified in options. Without this Dsn, the SDK will be disabled. */

  /** Array of set up integrations. */

  /** Number of calls being processed */

  /** Holds flushable  */

  // eslint-disable-next-line @typescript-eslint/ban-types

  /**
   * Initializes this client instance.
   *
   * @param options Options for the client.
   */
   constructor(options) {
    this._options = options;
    this._integrations = {};
    this._numProcessing = 0;
    this._outcomes = {};
    this._hooks = {};
    this._eventProcessors = [];

    if (options.dsn) {
      this._dsn = dsn_makeDsn(options.dsn);
    } else {
      debug_build_DEBUG_BUILD && logger_logger.warn('No DSN provided, client will not send events.');
    }

    if (this._dsn) {
      const url = getEnvelopeEndpointWithUrlEncodedAuth(
        this._dsn,
        options.tunnel,
        options._metadata ? options._metadata.sdk : undefined,
      );
      this._transport = options.transport({
        tunnel: this._options.tunnel,
        recordDroppedEvent: this.recordDroppedEvent.bind(this),
        ...options.transportOptions,
        url,
      });
    }

    // TODO(v9): Remove this deprecation warning
    const tracingOptions = ['enableTracing', 'tracesSampleRate', 'tracesSampler'] ;
    const undefinedOption = tracingOptions.find(option => option in options && options[option] == undefined);
    if (undefinedOption) {
      consoleSandbox(() => {
        // eslint-disable-next-line no-console
        console.warn(
          `[Sentry] Deprecation warning: \`${undefinedOption}\` is set to undefined, which leads to tracing being enabled. In v9, a value of \`undefined\` will result in tracing being disabled.`,
        );
      });
    }
  }

  /**
   * @inheritDoc
   */
   captureException(exception, hint, scope) {
    const eventId = misc_uuid4();

    // ensure we haven't captured this very object before
    if (checkOrSetAlreadyCaught(exception)) {
      debug_build_DEBUG_BUILD && logger_logger.log(ALREADY_SEEN_ERROR);
      return eventId;
    }

    const hintWithEventId = {
      event_id: eventId,
      ...hint,
    };

    this._process(
      this.eventFromException(exception, hintWithEventId).then(event =>
        this._captureEvent(event, hintWithEventId, scope),
      ),
    );

    return hintWithEventId.event_id;
  }

  /**
   * @inheritDoc
   */
   captureMessage(
    message,
    level,
    hint,
    currentScope,
  ) {
    const hintWithEventId = {
      event_id: misc_uuid4(),
      ...hint,
    };

    const eventMessage = isParameterizedString(message) ? message : String(message);

    const promisedEvent = is_isPrimitive(message)
      ? this.eventFromMessage(eventMessage, level, hintWithEventId)
      : this.eventFromException(message, hintWithEventId);

    this._process(promisedEvent.then(event => this._captureEvent(event, hintWithEventId, currentScope)));

    return hintWithEventId.event_id;
  }

  /**
   * @inheritDoc
   */
   captureEvent(event, hint, currentScope) {
    const eventId = misc_uuid4();

    // ensure we haven't captured this very object before
    if (hint && hint.originalException && checkOrSetAlreadyCaught(hint.originalException)) {
      debug_build_DEBUG_BUILD && logger_logger.log(ALREADY_SEEN_ERROR);
      return eventId;
    }

    const hintWithEventId = {
      event_id: eventId,
      ...hint,
    };

    const sdkProcessingMetadata = event.sdkProcessingMetadata || {};
    const capturedSpanScope = sdkProcessingMetadata.capturedSpanScope;

    this._process(this._captureEvent(event, hintWithEventId, capturedSpanScope || currentScope));

    return hintWithEventId.event_id;
  }

  /**
   * @inheritDoc
   */
   captureSession(session) {
    if (!(typeof session.release === 'string')) {
      debug_build_DEBUG_BUILD && logger_logger.warn('Discarded session because of missing or non-string release');
    } else {
      this.sendSession(session);
      // After sending, we set init false to indicate it's not the first occurrence
      updateSession(session, { init: false });
    }
  }

  /**
   * @inheritDoc
   */
   getDsn() {
    return this._dsn;
  }

  /**
   * @inheritDoc
   */
   getOptions() {
    return this._options;
  }

  /**
   * @see SdkMetadata
   *
   * @return The metadata of the SDK
   */
   getSdkMetadata() {
    return this._options._metadata;
  }

  /**
   * @inheritDoc
   */
   getTransport() {
    return this._transport;
  }

  /**
   * @inheritDoc
   */
   flush(timeout) {
    const transport = this._transport;
    if (transport) {
      this.emit('flush');
      return this._isClientDoneProcessing(timeout).then(clientFinished => {
        return transport.flush(timeout).then(transportFlushed => clientFinished && transportFlushed);
      });
    } else {
      return resolvedSyncPromise(true);
    }
  }

  /**
   * @inheritDoc
   */
   close(timeout) {
    return this.flush(timeout).then(result => {
      this.getOptions().enabled = false;
      this.emit('close');
      return result;
    });
  }

  /** Get all installed event processors. */
   getEventProcessors() {
    return this._eventProcessors;
  }

  /** @inheritDoc */
   addEventProcessor(eventProcessor) {
    this._eventProcessors.push(eventProcessor);
  }

  /** @inheritdoc */
   init() {
    if (
      this._isEnabled() ||
      // Force integrations to be setup even if no DSN was set when we have
      // Spotlight enabled. This is particularly important for browser as we
      // don't support the `spotlight` option there and rely on the users
      // adding the `spotlightBrowserIntegration()` to their integrations which
      // wouldn't get initialized with the check below when there's no DSN set.
      this._options.integrations.some(({ name }) => name.startsWith('Spotlight'))
    ) {
      this._setupIntegrations();
    }
  }

  /**
   * Gets an installed integration by its name.
   *
   * @returns The installed integration or `undefined` if no integration with that `name` was installed.
   */
   getIntegrationByName(integrationName) {
    return this._integrations[integrationName] ;
  }

  /**
   * @inheritDoc
   */
   addIntegration(integration) {
    const isAlreadyInstalled = this._integrations[integration.name];

    // This hook takes care of only installing if not already installed
    setupIntegration(this, integration, this._integrations);
    // Here we need to check manually to make sure to not run this multiple times
    if (!isAlreadyInstalled) {
      afterSetupIntegrations(this, [integration]);
    }
  }

  /**
   * @inheritDoc
   */
   sendEvent(event, hint = {}) {
    this.emit('beforeSendEvent', event, hint);

    let env = createEventEnvelope(event, this._dsn, this._options._metadata, this._options.tunnel);

    for (const attachment of hint.attachments || []) {
      env = addItemToEnvelope(env, createAttachmentEnvelopeItem(attachment));
    }

    const promise = this.sendEnvelope(env);
    if (promise) {
      promise.then(sendResponse => this.emit('afterSendEvent', event, sendResponse), null);
    }
  }

  /**
   * @inheritDoc
   */
   sendSession(session) {
    const env = createSessionEnvelope(session, this._dsn, this._options._metadata, this._options.tunnel);

    // sendEnvelope should not throw
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    this.sendEnvelope(env);
  }

  /**
   * @inheritDoc
   */
   recordDroppedEvent(reason, category, eventOrCount) {
    if (this._options.sendClientReports) {
      // TODO v9: We do not need the `event` passed as third argument anymore, and can possibly remove this overload
      // If event is passed as third argument, we assume this is a count of 1
      const count = typeof eventOrCount === 'number' ? eventOrCount : 1;

      // We want to track each category (error, transaction, session, replay_event) separately
      // but still keep the distinction between different type of outcomes.
      // We could use nested maps, but it's much easier to read and type this way.
      // A correct type for map-based implementation if we want to go that route
      // would be `Partial<Record<SentryRequestType, Partial<Record<Outcome, number>>>>`
      // With typescript 4.1 we could even use template literal types
      const key = `${reason}:${category}`;
      debug_build_DEBUG_BUILD && logger_logger.log(`Recording outcome: "${key}"${count > 1 ? ` (${count} times)` : ''}`);
      this._outcomes[key] = (this._outcomes[key] || 0) + count;
    }
  }

  // Keep on() & emit() signatures in sync with types' client.ts interface
  /* eslint-disable @typescript-eslint/unified-signatures */

  /** @inheritdoc */

  /** @inheritdoc */
   on(hook, callback) {
    const hooks = (this._hooks[hook] = this._hooks[hook] || []);

    // @ts-expect-error We assume the types are correct
    hooks.push(callback);

    // This function returns a callback execution handler that, when invoked,
    // deregisters a callback. This is crucial for managing instances where callbacks
    // need to be unregistered to prevent self-referencing in callback closures,
    // ensuring proper garbage collection.
    return () => {
      // @ts-expect-error We assume the types are correct
      const cbIndex = hooks.indexOf(callback);
      if (cbIndex > -1) {
        hooks.splice(cbIndex, 1);
      }
    };
  }

  /** @inheritdoc */

  /** @inheritdoc */
   emit(hook, ...rest) {
    const callbacks = this._hooks[hook];
    if (callbacks) {
      callbacks.forEach(callback => callback(...rest));
    }
  }

  /**
   * @inheritdoc
   */
   sendEnvelope(envelope) {
    this.emit('beforeEnvelope', envelope);

    if (this._isEnabled() && this._transport) {
      return this._transport.send(envelope).then(null, reason => {
        debug_build_DEBUG_BUILD && logger_logger.error('Error while sending envelope:', reason);
        return reason;
      });
    }

    debug_build_DEBUG_BUILD && logger_logger.error('Transport disabled');

    return resolvedSyncPromise({});
  }

  /* eslint-enable @typescript-eslint/unified-signatures */

  /** Setup integrations for this client. */
   _setupIntegrations() {
    const { integrations } = this._options;
    this._integrations = setupIntegrations(this, integrations);
    afterSetupIntegrations(this, integrations);
  }

  /** Updates existing session based on the provided event */
   _updateSessionFromEvent(session, event) {
    let crashed = false;
    let errored = false;
    const exceptions = event.exception && event.exception.values;

    if (exceptions) {
      errored = true;

      for (const ex of exceptions) {
        const mechanism = ex.mechanism;
        if (mechanism && mechanism.handled === false) {
          crashed = true;
          break;
        }
      }
    }

    // A session is updated and that session update is sent in only one of the two following scenarios:
    // 1. Session with non terminal status and 0 errors + an error occurred -> Will set error count to 1 and send update
    // 2. Session with non terminal status and 1 error + a crash occurred -> Will set status crashed and send update
    const sessionNonTerminal = session.status === 'ok';
    const shouldUpdateAndSend = (sessionNonTerminal && session.errors === 0) || (sessionNonTerminal && crashed);

    if (shouldUpdateAndSend) {
      updateSession(session, {
        ...(crashed && { status: 'crashed' }),
        errors: session.errors || Number(errored || crashed),
      });
      this.captureSession(session);
    }
  }

  /**
   * Determine if the client is finished processing. Returns a promise because it will wait `timeout` ms before saying
   * "no" (resolving to `false`) in order to give the client a chance to potentially finish first.
   *
   * @param timeout The time, in ms, after which to resolve to `false` if the client is still busy. Passing `0` (or not
   * passing anything) will make the promise wait as long as it takes for processing to finish before resolving to
   * `true`.
   * @returns A promise which will resolve to `true` if processing is already done or finishes before the timeout, and
   * `false` otherwise
   */
   _isClientDoneProcessing(timeout) {
    return new SyncPromise(resolve => {
      let ticked = 0;
      const tick = 1;

      const interval = setInterval(() => {
        if (this._numProcessing == 0) {
          clearInterval(interval);
          resolve(true);
        } else {
          ticked += tick;
          if (timeout && ticked >= timeout) {
            clearInterval(interval);
            resolve(false);
          }
        }
      }, tick);
    });
  }

  /** Determines whether this SDK is enabled and a transport is present. */
   _isEnabled() {
    return this.getOptions().enabled !== false && this._transport !== undefined;
  }

  /**
   * Adds common information to events.
   *
   * The information includes release and environment from `options`,
   * breadcrumbs and context (extra, tags and user) from the scope.
   *
   * Information that is already present in the event is never overwritten. For
   * nested objects, such as the context, keys are merged.
   *
   * @param event The original event.
   * @param hint May contain additional information about the original exception.
   * @param currentScope A scope containing event metadata.
   * @returns A new event with more information.
   */
   _prepareEvent(
    event,
    hint,
    currentScope = currentScopes_getCurrentScope(),
    isolationScope = currentScopes_getIsolationScope(),
  ) {
    const options = this.getOptions();
    const integrations = Object.keys(this._integrations);
    if (!hint.integrations && integrations.length > 0) {
      hint.integrations = integrations;
    }

    this.emit('preprocessEvent', event, hint);

    if (!event.type) {
      isolationScope.setLastEventId(event.event_id || hint.event_id);
    }

    return prepareEvent(options, event, hint, currentScope, this, isolationScope).then(evt => {
      if (evt === null) {
        return evt;
      }

      evt.contexts = {
        trace: getTraceContextFromScope(currentScope),
        ...evt.contexts,
      };

      const dynamicSamplingContext = getDynamicSamplingContextFromScope(this, currentScope);

      evt.sdkProcessingMetadata = {
        dynamicSamplingContext,
        ...evt.sdkProcessingMetadata,
      };

      return evt;
    });
  }

  /**
   * Processes the event and logs an error in case of rejection
   * @param event
   * @param hint
   * @param scope
   */
   _captureEvent(event, hint = {}, scope) {
    return this._processEvent(event, hint, scope).then(
      finalEvent => {
        return finalEvent.event_id;
      },
      reason => {
        if (debug_build_DEBUG_BUILD) {
          // If something's gone wrong, log the error as a warning. If it's just us having used a `SentryError` for
          // control flow, log just the message (no stack) as a log-level log.
          const sentryError = reason ;
          if (sentryError.logLevel === 'log') {
            logger_logger.log(sentryError.message);
          } else {
            logger_logger.warn(sentryError);
          }
        }
        return undefined;
      },
    );
  }

  /**
   * Processes an event (either error or message) and sends it to Sentry.
   *
   * This also adds breadcrumbs and context information to the event. However,
   * platform specific meta data (such as the User's IP address) must be added
   * by the SDK implementor.
   *
   *
   * @param event The event to send to Sentry.
   * @param hint May contain additional information about the original exception.
   * @param currentScope A scope containing event metadata.
   * @returns A SyncPromise that resolves with the event or rejects in case event was/will not be send.
   */
   _processEvent(event, hint, currentScope) {
    const options = this.getOptions();
    const { sampleRate } = options;

    const isTransaction = isTransactionEvent(event);
    const isError = baseclient_isErrorEvent(event);
    const eventType = event.type || 'error';
    const beforeSendLabel = `before send for type \`${eventType}\``;

    // 1.0 === 100% events are sent
    // 0.0 === 0% events are sent
    // Sampling for transaction happens somewhere else
    const parsedSampleRate = typeof sampleRate === 'undefined' ? undefined : parseSampleRate(sampleRate);
    if (isError && typeof parsedSampleRate === 'number' && Math.random() > parsedSampleRate) {
      this.recordDroppedEvent('sample_rate', 'error', event);
      return rejectedSyncPromise(
        new SentryError(
          `Discarding event because it's not included in the random sample (sampling rate = ${sampleRate})`,
          'log',
        ),
      );
    }

    const dataCategory = eventType === 'replay_event' ? 'replay' : eventType;

    const sdkProcessingMetadata = event.sdkProcessingMetadata || {};
    const capturedSpanIsolationScope = sdkProcessingMetadata.capturedSpanIsolationScope;

    return this._prepareEvent(event, hint, currentScope, capturedSpanIsolationScope)
      .then(prepared => {
        if (prepared === null) {
          this.recordDroppedEvent('event_processor', dataCategory, event);
          throw new SentryError('An event processor returned `null`, will not send event.', 'log');
        }

        const isInternalException = hint.data && (hint.data ).__sentry__ === true;
        if (isInternalException) {
          return prepared;
        }

        const result = processBeforeSend(this, options, prepared, hint);
        return _validateBeforeSendResult(result, beforeSendLabel);
      })
      .then(processedEvent => {
        if (processedEvent === null) {
          this.recordDroppedEvent('before_send', dataCategory, event);
          if (isTransaction) {
            const spans = event.spans || [];
            // the transaction itself counts as one span, plus all the child spans that are added
            const spanCount = 1 + spans.length;
            this.recordDroppedEvent('before_send', 'span', spanCount);
          }
          throw new SentryError(`${beforeSendLabel} returned \`null\`, will not send event.`, 'log');
        }

        const session = currentScope && currentScope.getSession();
        if (!isTransaction && session) {
          this._updateSessionFromEvent(session, processedEvent);
        }

        if (isTransaction) {
          const spanCountBefore =
            (processedEvent.sdkProcessingMetadata && processedEvent.sdkProcessingMetadata.spanCountBeforeProcessing) ||
            0;
          const spanCountAfter = processedEvent.spans ? processedEvent.spans.length : 0;

          const droppedSpanCount = spanCountBefore - spanCountAfter;
          if (droppedSpanCount > 0) {
            this.recordDroppedEvent('before_send', 'span', droppedSpanCount);
          }
        }

        // None of the Sentry built event processor will update transaction name,
        // so if the transaction name has been changed by an event processor, we know
        // it has to come from custom event processor added by a user
        const transactionInfo = processedEvent.transaction_info;
        if (isTransaction && transactionInfo && processedEvent.transaction !== event.transaction) {
          const source = 'custom';
          processedEvent.transaction_info = {
            ...transactionInfo,
            source,
          };
        }

        this.sendEvent(processedEvent, hint);
        return processedEvent;
      })
      .then(null, reason => {
        if (reason instanceof SentryError) {
          throw reason;
        }

        this.captureException(reason, {
          data: {
            __sentry__: true,
          },
          originalException: reason,
        });
        throw new SentryError(
          `Event processing pipeline threw an error, original event will not be sent. Details have been sent as a new event.\nReason: ${reason}`,
        );
      });
  }

  /**
   * Occupies the client with processing and event
   */
   _process(promise) {
    this._numProcessing++;
    void promise.then(
      value => {
        this._numProcessing--;
        return value;
      },
      reason => {
        this._numProcessing--;
        return reason;
      },
    );
  }

  /**
   * Clears outcomes on this client and returns them.
   */
   _clearOutcomes() {
    const outcomes = this._outcomes;
    this._outcomes = {};
    return Object.entries(outcomes).map(([key, quantity]) => {
      const [reason, category] = key.split(':') ;
      return {
        reason,
        category,
        quantity,
      };
    });
  }

  /**
   * Sends client reports as an envelope.
   */
   _flushOutcomes() {
    debug_build_DEBUG_BUILD && logger_logger.log('Flushing outcomes...');

    const outcomes = this._clearOutcomes();

    if (outcomes.length === 0) {
      debug_build_DEBUG_BUILD && logger_logger.log('No outcomes to send');
      return;
    }

    // This is really the only place where we want to check for a DSN and only send outcomes then
    if (!this._dsn) {
      debug_build_DEBUG_BUILD && logger_logger.log('No dsn provided, will not send outcomes');
      return;
    }

    debug_build_DEBUG_BUILD && logger_logger.log('Sending outcomes:', outcomes);

    const envelope = createClientReportEnvelope(outcomes, this._options.tunnel && dsn_dsnToString(this._dsn));

    // sendEnvelope should not throw
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    this.sendEnvelope(envelope);
  }

  /**
   * @inheritDoc
   */

}

/**
 * Verifies that return value of configured `beforeSend` or `beforeSendTransaction` is of expected type, and returns the value if so.
 */
function _validateBeforeSendResult(
  beforeSendResult,
  beforeSendLabel,
) {
  const invalidValueError = `${beforeSendLabel} must return \`null\` or a valid event.`;
  if (is_isThenable(beforeSendResult)) {
    return beforeSendResult.then(
      event => {
        if (!isPlainObject(event) && event !== null) {
          throw new SentryError(invalidValueError);
        }
        return event;
      },
      e => {
        throw new SentryError(`${beforeSendLabel} rejected with ${e}`);
      },
    );
  } else if (!isPlainObject(beforeSendResult) && beforeSendResult !== null) {
    throw new SentryError(invalidValueError);
  }
  return beforeSendResult;
}

/**
 * Process the matching `beforeSendXXX` callback.
 */
function processBeforeSend(
  client,
  options,
  event,
  hint,
) {
  const { beforeSend, beforeSendTransaction, beforeSendSpan } = options;

  if (baseclient_isErrorEvent(event) && beforeSend) {
    return beforeSend(event, hint);
  }

  if (isTransactionEvent(event)) {
    if (event.spans && beforeSendSpan) {
      const processedSpans = [];
      for (const span of event.spans) {
        const processedSpan = beforeSendSpan(span);
        if (processedSpan) {
          processedSpans.push(processedSpan);
        } else {
          spanUtils_showSpanDropWarning();
          client.recordDroppedEvent('before_send', 'span');
        }
      }
      event.spans = processedSpans;
    }

    if (beforeSendTransaction) {
      if (event.spans) {
        // We store the # of spans before processing in SDK metadata,
        // so we can compare it afterwards to determine how many spans were dropped
        const spanCountBefore = event.spans.length;
        event.sdkProcessingMetadata = {
          ...event.sdkProcessingMetadata,
          spanCountBeforeProcessing: spanCountBefore,
        };
      }
      return beforeSendTransaction(event, hint);
    }
  }

  return event;
}

function baseclient_isErrorEvent(event) {
  return event.type === undefined;
}

function isTransactionEvent(event) {
  return event.type === 'transaction';
}


//# sourceMappingURL=baseclient.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/env.js
/*
 * This module exists for optimizations in the build process through rollup and terser.  We define some global
 * constants, which can be overridden during build. By guarding certain pieces of code with functions that return these
 * constants, we can control whether or not they appear in the final bundle. (Any code guarded by a false condition will
 * never run, and will hence be dropped during treeshaking.) The two primary uses for this are stripping out calls to
 * `logger` and preventing node-related code from appearing in browser bundles.
 *
 * Attention:
 * This file should not be used to define constants/flags that are intended to be used for tree-shaking conducted by
 * users. These flags should live in their respective packages, as we identified user tooling (specifically webpack)
 * having issues tree-shaking these constants across package boundaries.
 * An example for this is the __SENTRY_DEBUG__ constant. It is declared in each package individually because we want
 * users to be able to shake away expressions that it guards.
 */

/**
 * Figures out if we're building a browser bundle.
 *
 * @returns true if this is a browser bundle build.
 */
function isBrowserBundle() {
  return typeof __SENTRY_BROWSER_BUNDLE__ !== 'undefined' && !!__SENTRY_BROWSER_BUNDLE__;
}

/**
 * Get source of SDK.
 */
function getSDKSource() {
  // This comment is used to identify this line in the CDN bundle build step and replace this with "return 'cdn';"
  /* __SENTRY_SDK_SOURCE__ */ return 'npm';
}


//# sourceMappingURL=env.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils/sdkMetadata.js


/**
 * A builder for the SDK metadata in the options for the SDK initialization.
 *
 * Note: This function is identical to `buildMetadata` in Remix and NextJS and SvelteKit.
 * We don't extract it for bundle size reasons.
 * @see https://github.com/getsentry/sentry-javascript/pull/7404
 * @see https://github.com/getsentry/sentry-javascript/pull/4196
 *
 * If you make changes to this function consider updating the others as well.
 *
 * @param options SDK options object that gets mutated
 * @param names list of package names
 */
function applySdkMetadata(options, name, names = [name], source = 'npm') {
  const metadata = options._metadata || {};

  if (!metadata.sdk) {
    metadata.sdk = {
      name: `sentry.javascript.${name}`,
      packages: names.map(name => ({
        name: `${source}:@sentry/${name}`,
        version: SDK_VERSION,
      })),
      version: SDK_VERSION,
    };
  }

  options._metadata = metadata;
}


//# sourceMappingURL=sdkMetadata.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/debug-build.js
/**
 * This serves as a build time flag that will be true by default, but false in non-debug builds or if users replace `__SENTRY_DEBUG__` in their generated code.
 *
 * ATTENTION: This constant must never cross package boundaries (i.e. be exported) to guarantee that it can be used for tree shaking.
 */
const esm_debug_build_DEBUG_BUILD = (typeof __SENTRY_DEBUG__ === 'undefined' || __SENTRY_DEBUG__);


//# sourceMappingURL=debug-build.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/eventbuilder.js


/**
 * This function creates an exception from a JavaScript Error
 */
function exceptionFromError(stackParser, ex) {
  // Get the frames first since Opera can lose the stack if we touch anything else first
  const frames = parseStackFrames(stackParser, ex);

  const exception = {
    type: extractType(ex),
    value: extractMessage(ex),
  };

  if (frames.length) {
    exception.stacktrace = { frames };
  }

  if (exception.type === undefined && exception.value === '') {
    exception.value = 'Unrecoverable error caught';
  }

  return exception;
}

function eventFromPlainObject(
  stackParser,
  exception,
  syntheticException,
  isUnhandledRejection,
) {
  const client = currentScopes_getClient();
  const normalizeDepth = client && client.getOptions().normalizeDepth;

  // If we can, we extract an exception from the object properties
  const errorFromProp = getErrorPropertyFromObject(exception);

  const extra = {
    __serialized__: normalizeToSize(exception, normalizeDepth),
  };

  if (errorFromProp) {
    return {
      exception: {
        values: [exceptionFromError(stackParser, errorFromProp)],
      },
      extra,
    };
  }

  const event = {
    exception: {
      values: [
        {
          type: isEvent(exception) ? exception.constructor.name : isUnhandledRejection ? 'UnhandledRejection' : 'Error',
          value: getNonErrorObjectExceptionValue(exception, { isUnhandledRejection }),
        } ,
      ],
    },
    extra,
  } ;

  if (syntheticException) {
    const frames = parseStackFrames(stackParser, syntheticException);
    if (frames.length) {
      // event.exception.values[0] has been set above
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      event.exception.values[0].stacktrace = { frames };
    }
  }

  return event;
}

function eventFromError(stackParser, ex) {
  return {
    exception: {
      values: [exceptionFromError(stackParser, ex)],
    },
  };
}

/** Parses stack frames from an error */
function parseStackFrames(
  stackParser,
  ex,
) {
  // Access and store the stacktrace property before doing ANYTHING
  // else to it because Opera is not very good at providing it
  // reliably in other circumstances.
  const stacktrace = ex.stacktrace || ex.stack || '';

  const skipLines = getSkipFirstStackStringLines(ex);
  const framesToPop = getPopFirstTopFrames(ex);

  try {
    return stackParser(stacktrace, skipLines, framesToPop);
  } catch (e) {
    // no-empty
  }

  return [];
}

// Based on our own mapping pattern - https://github.com/getsentry/sentry/blob/9f08305e09866c8bd6d0c24f5b0aabdd7dd6c59c/src/sentry/lang/javascript/errormapping.py#L83-L108
const reactMinifiedRegexp = /Minified React error #\d+;/i;

/**
 * Certain known React errors contain links that would be falsely
 * parsed as frames. This function check for these errors and
 * returns number of the stack string lines to skip.
 */
function getSkipFirstStackStringLines(ex) {
  if (ex && reactMinifiedRegexp.test(ex.message)) {
    return 1;
  }

  return 0;
}

/**
 * If error has `framesToPop` property, it means that the
 * creator tells us the first x frames will be useless
 * and should be discarded. Typically error from wrapper function
 * which don't point to the actual location in the developer's code.
 *
 * Example: https://github.com/zertosh/invariant/blob/master/invariant.js#L46
 */
function getPopFirstTopFrames(ex) {
  if (typeof ex.framesToPop === 'number') {
    return ex.framesToPop;
  }

  return 0;
}

// https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/Exception
// @ts-expect-error - WebAssembly.Exception is a valid class
function isWebAssemblyException(exception) {
  // Check for support
  // @ts-expect-error - WebAssembly.Exception is a valid class
  if (typeof WebAssembly !== 'undefined' && typeof WebAssembly.Exception !== 'undefined') {
    // @ts-expect-error - WebAssembly.Exception is a valid class
    return exception instanceof WebAssembly.Exception;
  } else {
    return false;
  }
}

/**
 * Extracts from errors what we use as the exception `type` in error events.
 *
 * Usually, this is the `name` property on Error objects but WASM errors need to be treated differently.
 */
function extractType(ex) {
  const name = ex && ex.name;

  // The name for WebAssembly.Exception Errors needs to be extracted differently.
  // Context: https://github.com/getsentry/sentry-javascript/issues/13787
  if (!name && isWebAssemblyException(ex)) {
    // Emscripten sets array[type, message] to the "message" property on the WebAssembly.Exception object
    const hasTypeInMessage = ex.message && Array.isArray(ex.message) && ex.message.length == 2;
    return hasTypeInMessage ? ex.message[0] : 'WebAssembly.Exception';
  }

  return name;
}

/**
 * There are cases where stacktrace.message is an Event object
 * https://github.com/getsentry/sentry-javascript/issues/1949
 * In this specific case we try to extract stacktrace.message.error.message
 */
function extractMessage(ex) {
  const message = ex && ex.message;

  if (!message) {
    return 'No error message';
  }

  if (message.error && typeof message.error.message === 'string') {
    return message.error.message;
  }

  // Emscripten sets array[type, message] to the "message" property on the WebAssembly.Exception object
  if (isWebAssemblyException(ex) && Array.isArray(ex.message) && ex.message.length == 2) {
    return ex.message[1];
  }

  return message;
}

/**
 * Creates an {@link Event} from all inputs to `captureException` and non-primitive inputs to `captureMessage`.
 * @hidden
 */
function eventFromException(
  stackParser,
  exception,
  hint,
  attachStacktrace,
) {
  const syntheticException = (hint && hint.syntheticException) || undefined;
  const event = eventFromUnknownInput(stackParser, exception, syntheticException, attachStacktrace);
  addExceptionMechanism(event); // defaults to { type: 'generic', handled: true }
  event.level = 'error';
  if (hint && hint.event_id) {
    event.event_id = hint.event_id;
  }
  return resolvedSyncPromise(event);
}

/**
 * Builds and Event from a Message
 * @hidden
 */
function eventFromMessage(
  stackParser,
  message,
  level = 'info',
  hint,
  attachStacktrace,
) {
  const syntheticException = (hint && hint.syntheticException) || undefined;
  const event = eventFromString(stackParser, message, syntheticException, attachStacktrace);
  event.level = level;
  if (hint && hint.event_id) {
    event.event_id = hint.event_id;
  }
  return resolvedSyncPromise(event);
}

/**
 * @hidden
 */
function eventFromUnknownInput(
  stackParser,
  exception,
  syntheticException,
  attachStacktrace,
  isUnhandledRejection,
) {
  let event;

  if (isErrorEvent(exception ) && (exception ).error) {
    // If it is an ErrorEvent with `error` property, extract it to get actual Error
    const errorEvent = exception ;
    return eventFromError(stackParser, errorEvent.error );
  }

  // If it is a `DOMError` (which is a legacy API, but still supported in some browsers) then we just extract the name
  // and message, as it doesn't provide anything else. According to the spec, all `DOMExceptions` should also be
  // `Error`s, but that's not the case in IE11, so in that case we treat it the same as we do a `DOMError`.
  //
  // https://developer.mozilla.org/en-US/docs/Web/API/DOMError
  // https://developer.mozilla.org/en-US/docs/Web/API/DOMException
  // https://webidl.spec.whatwg.org/#es-DOMException-specialness
  if (isDOMError(exception) || isDOMException(exception )) {
    const domException = exception ;

    if ('stack' in (exception )) {
      event = eventFromError(stackParser, exception );
    } else {
      const name = domException.name || (isDOMError(domException) ? 'DOMError' : 'DOMException');
      const message = domException.message ? `${name}: ${domException.message}` : name;
      event = eventFromString(stackParser, message, syntheticException, attachStacktrace);
      addExceptionTypeValue(event, message);
    }
    if ('code' in domException) {
      // eslint-disable-next-line deprecation/deprecation
      event.tags = { ...event.tags, 'DOMException.code': `${domException.code}` };
    }

    return event;
  }
  if (isError(exception)) {
    // we have a real Error object, do nothing
    return eventFromError(stackParser, exception);
  }
  if (isPlainObject(exception) || isEvent(exception)) {
    // If it's a plain object or an instance of `Event` (the built-in JS kind, not this SDK's `Event` type), serialize
    // it manually. This will allow us to group events based on top-level keys which is much better than creating a new
    // group on any key/value change.
    const objectException = exception ;
    event = eventFromPlainObject(stackParser, objectException, syntheticException, isUnhandledRejection);
    addExceptionMechanism(event, {
      synthetic: true,
    });
    return event;
  }

  // If none of previous checks were valid, then it means that it's not:
  // - an instance of DOMError
  // - an instance of DOMException
  // - an instance of Event
  // - an instance of Error
  // - a valid ErrorEvent (one with an error property)
  // - a plain Object
  //
  // So bail out and capture it as a simple message:
  event = eventFromString(stackParser, exception , syntheticException, attachStacktrace);
  addExceptionTypeValue(event, `${exception}`, undefined);
  addExceptionMechanism(event, {
    synthetic: true,
  });

  return event;
}

function eventFromString(
  stackParser,
  message,
  syntheticException,
  attachStacktrace,
) {
  const event = {};

  if (attachStacktrace && syntheticException) {
    const frames = parseStackFrames(stackParser, syntheticException);
    if (frames.length) {
      event.exception = {
        values: [{ value: message, stacktrace: { frames } }],
      };
    }
    addExceptionMechanism(event, { synthetic: true });
  }

  if (isParameterizedString(message)) {
    const { __sentry_template_string__, __sentry_template_values__ } = message;

    event.logentry = {
      message: __sentry_template_string__,
      params: __sentry_template_values__,
    };
    return event;
  }

  event.message = message;
  return event;
}

function getNonErrorObjectExceptionValue(
  exception,
  { isUnhandledRejection },
) {
  const keys = extractExceptionKeysForMessage(exception);
  const captureType = isUnhandledRejection ? 'promise rejection' : 'exception';

  // Some ErrorEvent instances do not have an `error` property, which is why they are not handled before
  // We still want to try to get a decent message for these cases
  if (isErrorEvent(exception)) {
    return `Event \`ErrorEvent\` captured as ${captureType} with message \`${exception.message}\``;
  }

  if (isEvent(exception)) {
    const className = getObjectClassName(exception);
    return `Event \`${className}\` (type=${exception.type}) captured as ${captureType}`;
  }

  return `Object captured as ${captureType} with keys: ${keys}`;
}

function getObjectClassName(obj) {
  try {
    const prototype = Object.getPrototypeOf(obj);
    return prototype ? prototype.constructor.name : undefined;
  } catch (e) {
    // ignore errors here
  }
}

/** If a plain object has a property that is an `Error`, return this error. */
function getErrorPropertyFromObject(obj) {
  for (const prop in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, prop)) {
      const value = obj[prop];
      if (value instanceof Error) {
        return value;
      }
    }
  }

  return undefined;
}


//# sourceMappingURL=eventbuilder.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/exports.js











/**
 * Captures an exception event and sends it to Sentry.
 *
 * @param exception The exception to capture.
 * @param hint Optional additional data to attach to the Sentry event.
 * @returns the id of the captured Sentry event.
 */
function captureException(exception, hint) {
  return currentScopes_getCurrentScope().captureException(exception, parseEventHintOrCaptureContext(hint));
}

/**
 * Captures a message event and sends it to Sentry.
 *
 * @param message The message to send to Sentry.
 * @param captureContext Define the level of the message or pass in additional data to attach to the message.
 * @returns the id of the captured message.
 */
function captureMessage(message, captureContext) {
  // This is necessary to provide explicit scopes upgrade, without changing the original
  // arity of the `captureMessage(message, level)` method.
  const level = typeof captureContext === 'string' ? captureContext : undefined;
  const context = typeof captureContext !== 'string' ? { captureContext } : undefined;
  return getCurrentScope().captureMessage(message, level, context);
}

/**
 * Captures a manually created event and sends it to Sentry.
 *
 * @param event The event to send to Sentry.
 * @param hint Optional additional data to attach to the Sentry event.
 * @returns the id of the captured event.
 */
function captureEvent(event, hint) {
  return currentScopes_getCurrentScope().captureEvent(event, hint);
}

/**
 * Sets context data with the given name.
 * @param name of the context
 * @param context Any kind of data. This data will be normalized.
 */
function setContext(name, context) {
  getIsolationScope().setContext(name, context);
}

/**
 * Set an object that will be merged sent as extra data with the event.
 * @param extras Extras object to merge into current context.
 */
function setExtras(extras) {
  getIsolationScope().setExtras(extras);
}

/**
 * Set key:value that will be sent as extra data with the event.
 * @param key String of extra
 * @param extra Any kind of data. This data will be normalized.
 */
function setExtra(key, extra) {
  getIsolationScope().setExtra(key, extra);
}

/**
 * Set an object that will be merged sent as tags data with the event.
 * @param tags Tags context object to merge into current context.
 */
function setTags(tags) {
  getIsolationScope().setTags(tags);
}

/**
 * Set key:value that will be sent as tags data with the event.
 *
 * Can also be used to unset a tag, by passing `undefined`.
 *
 * @param key String key of tag
 * @param value Value of tag
 */
function setTag(key, value) {
  getIsolationScope().setTag(key, value);
}

/**
 * Updates user context information for future events.
 *
 * @param user User context object to be set in the current context. Pass `null` to unset the user.
 */
function setUser(user) {
  getIsolationScope().setUser(user);
}

/**
 * The last error event id of the isolation scope.
 *
 * Warning: This function really returns the last recorded error event id on the current
 * isolation scope. If you call this function after handling a certain error and another error
 * is captured in between, the last one is returned instead of the one you might expect.
 * Also, ids of events that were never sent to Sentry (for example because
 * they were dropped in `beforeSend`) could be returned.
 *
 * @returns The last event id of the isolation scope.
 */
function exports_lastEventId() {
  return getIsolationScope().lastEventId();
}

/**
 * Create a cron monitor check in and send it to Sentry.
 *
 * @param checkIn An object that describes a check in.
 * @param upsertMonitorConfig An optional object that describes a monitor config. Use this if you want
 * to create a monitor automatically when sending a check in.
 */
function captureCheckIn(checkIn, upsertMonitorConfig) {
  const scope = getCurrentScope();
  const client = getClient();
  if (!client) {
    DEBUG_BUILD && logger.warn('Cannot capture check-in. No client defined.');
  } else if (!client.captureCheckIn) {
    DEBUG_BUILD && logger.warn('Cannot capture check-in. Client does not support sending check-ins.');
  } else {
    return client.captureCheckIn(checkIn, upsertMonitorConfig, scope);
  }

  return uuid4();
}

/**
 * Wraps a callback with a cron monitor check in. The check in will be sent to Sentry when the callback finishes.
 *
 * @param monitorSlug The distinct slug of the monitor.
 * @param upsertMonitorConfig An optional object that describes a monitor config. Use this if you want
 * to create a monitor automatically when sending a check in.
 */
function withMonitor(
  monitorSlug,
  callback,
  upsertMonitorConfig,
) {
  const checkInId = captureCheckIn({ monitorSlug, status: 'in_progress' }, upsertMonitorConfig);
  const now = timestampInSeconds();

  function finishCheckIn(status) {
    captureCheckIn({ monitorSlug, status, checkInId, duration: timestampInSeconds() - now });
  }

  return withIsolationScope(() => {
    let maybePromiseResult;
    try {
      maybePromiseResult = callback();
    } catch (e) {
      finishCheckIn('error');
      throw e;
    }

    if (isThenable(maybePromiseResult)) {
      Promise.resolve(maybePromiseResult).then(
        () => {
          finishCheckIn('ok');
        },
        e => {
          finishCheckIn('error');
          throw e;
        },
      );
    } else {
      finishCheckIn('ok');
    }

    return maybePromiseResult;
  });
}

/**
 * Call `flush()` on the current client, if there is one. See {@link Client.flush}.
 *
 * @param timeout Maximum time in ms the client should wait to flush its event queue. Omitting this parameter will cause
 * the client to wait until all events are sent before resolving the promise.
 * @returns A promise which resolves to `true` if the queue successfully drains before the timeout, or `false` if it
 * doesn't (or if there's no client defined).
 */
async function exports_flush(timeout) {
  const client = getClient();
  if (client) {
    return client.flush(timeout);
  }
  DEBUG_BUILD && logger.warn('Cannot flush events. No client defined.');
  return Promise.resolve(false);
}

/**
 * Call `close()` on the current client, if there is one. See {@link Client.close}.
 *
 * @param timeout Maximum time in ms the client should wait to flush its event queue before shutting down. Omitting this
 * parameter will cause the client to wait until all events are sent before disabling itself.
 * @returns A promise which resolves to `true` if the queue successfully drains before the timeout, or `false` if it
 * doesn't (or if there's no client defined).
 */
async function exports_close(timeout) {
  const client = getClient();
  if (client) {
    return client.close(timeout);
  }
  DEBUG_BUILD && logger.warn('Cannot flush events and disable SDK. No client defined.');
  return Promise.resolve(false);
}

/**
 * Returns true if Sentry has been properly initialized.
 */
function exports_isInitialized() {
  return !!getClient();
}

/** If the SDK is initialized & enabled. */
function isEnabled() {
  const client = getClient();
  return !!client && client.getOptions().enabled !== false && !!client.getTransport();
}

/**
 * Add an event processor.
 * This will be added to the current isolation scope, ensuring any event that is processed in the current execution
 * context will have the processor applied.
 */
function addEventProcessor(callback) {
  getIsolationScope().addEventProcessor(callback);
}

/**
 * Start a session on the current isolation scope.
 *
 * @param context (optional) additional properties to be applied to the returned session object
 *
 * @returns the new active session
 */
function startSession(context) {
  const client = currentScopes_getClient();
  const isolationScope = currentScopes_getIsolationScope();
  const currentScope = currentScopes_getCurrentScope();

  const { release, environment = DEFAULT_ENVIRONMENT } = (client && client.getOptions()) || {};

  // Will fetch userAgent if called from browser sdk
  const { userAgent } = worldwide_GLOBAL_OBJ.navigator || {};

  const session = makeSession({
    release,
    environment,
    user: currentScope.getUser() || isolationScope.getUser(),
    ...(userAgent && { userAgent }),
    ...context,
  });

  // End existing session if there's one
  const currentSession = isolationScope.getSession();
  if (currentSession && currentSession.status === 'ok') {
    updateSession(currentSession, { status: 'exited' });
  }

  endSession();

  // Afterwards we set the new session on the scope
  isolationScope.setSession(session);

  // TODO (v8): Remove this and only use the isolation scope(?).
  // For v7 though, we can't "soft-break" people using getCurrentHub().getScope().setSession()
  currentScope.setSession(session);

  return session;
}

/**
 * End the session on the current isolation scope.
 */
function endSession() {
  const isolationScope = currentScopes_getIsolationScope();
  const currentScope = currentScopes_getCurrentScope();

  const session = currentScope.getSession() || isolationScope.getSession();
  if (session) {
    closeSession(session);
  }
  _sendSessionUpdate();

  // the session is over; take it off of the scope
  isolationScope.setSession();

  // TODO (v8): Remove this and only use the isolation scope(?).
  // For v7 though, we can't "soft-break" people using getCurrentHub().getScope().setSession()
  currentScope.setSession();
}

/**
 * Sends the current Session on the scope
 */
function _sendSessionUpdate() {
  const isolationScope = currentScopes_getIsolationScope();
  const currentScope = currentScopes_getCurrentScope();
  const client = currentScopes_getClient();
  // TODO (v8): Remove currentScope and only use the isolation scope(?).
  // For v7 though, we can't "soft-break" people using getCurrentHub().getScope().setSession()
  const session = currentScope.getSession() || isolationScope.getSession();
  if (session && client) {
    client.captureSession(session);
  }
}

/**
 * Sends the current session on the scope to Sentry
 *
 * @param end If set the session will be marked as exited and removed from the scope.
 *            Defaults to `false`.
 */
function captureSession(end = false) {
  // both send the update and pull the session from the scope
  if (end) {
    endSession();
    return;
  }

  // only send the update
  _sendSessionUpdate();
}


//# sourceMappingURL=exports.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/helpers.js


const helpers_WINDOW = worldwide_GLOBAL_OBJ ;

let ignoreOnError = 0;

/**
 * @hidden
 */
function shouldIgnoreOnError() {
  return ignoreOnError > 0;
}

/**
 * @hidden
 */
function ignoreNextOnError() {
  // onerror should trigger before setTimeout
  ignoreOnError++;
  setTimeout(() => {
    ignoreOnError--;
  });
}

// eslint-disable-next-line @typescript-eslint/ban-types

/**
 * Instruments the given function and sends an event to Sentry every time the
 * function throws an exception.
 *
 * @param fn A function to wrap. It is generally safe to pass an unbound function, because the returned wrapper always
 * has a correct `this` context.
 * @returns The wrapped function.
 * @hidden
 */
function wrap(
  fn,
  options

 = {},
) {
  // for future readers what this does is wrap a function and then create
  // a bi-directional wrapping between them.
  //
  // example: wrapped = wrap(original);
  //  original.__sentry_wrapped__ -> wrapped
  //  wrapped.__sentry_original__ -> original

  function isFunction(fn) {
    return typeof fn === 'function';
  }

  if (!isFunction(fn)) {
    return fn;
  }

  try {
    // if we're dealing with a function that was previously wrapped, return
    // the original wrapper.
    const wrapper = (fn ).__sentry_wrapped__;
    if (wrapper) {
      if (typeof wrapper === 'function') {
        return wrapper;
      } else {
        // If we find that the `__sentry_wrapped__` function is not a function at the time of accessing it, it means
        // that something messed with it. In that case we want to return the originally passed function.
        return fn;
      }
    }

    // We don't wanna wrap it twice
    if (getOriginalFunction(fn)) {
      return fn;
    }
  } catch (e) {
    // Just accessing custom props in some Selenium environments
    // can cause a "Permission denied" exception (see raven-js#495).
    // Bail on wrapping and return the function as-is (defers to window.onerror).
    return fn;
  }

  // Wrap the function itself
  // It is important that `sentryWrapped` is not an arrow function to preserve the context of `this`
  const sentryWrapped = function ( ...args) {
    try {
      // Also wrap arguments that are themselves functions
      const wrappedArguments = args.map(arg => wrap(arg, options));

      // Attempt to invoke user-land function
      // NOTE: If you are a Sentry user, and you are seeing this stack frame, it
      //       means the sentry.javascript SDK caught an error invoking your application code. This
      //       is expected behavior and NOT indicative of a bug with sentry.javascript.
      return fn.apply(this, wrappedArguments);
    } catch (ex) {
      ignoreNextOnError();

      currentScopes_withScope(scope => {
        scope.addEventProcessor(event => {
          if (options.mechanism) {
            addExceptionTypeValue(event, undefined, undefined);
            addExceptionMechanism(event, options.mechanism);
          }

          event.extra = {
            ...event.extra,
            arguments: args,
          };

          return event;
        });

        captureException(ex);
      });

      throw ex;
    }
  } ;

  // Wrap the wrapped function in a proxy, to ensure any other properties of the original function remain available
  try {
    for (const property in fn) {
      if (Object.prototype.hasOwnProperty.call(fn, property)) {
        sentryWrapped[property ] = fn[property ];
      }
    }
  } catch (e2) {
    // Accessing some objects may throw
    // ref: https://github.com/getsentry/sentry-javascript/issues/1168
  }

  // Signal that this function has been wrapped/filled already
  // for both debugging and to prevent it to being wrapped/filled twice
  markFunctionWrapped(sentryWrapped, fn);

  object_addNonEnumerableProperty(fn, '__sentry_wrapped__', sentryWrapped);

  // Restore original function name (not all browsers allow that)
  try {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const descriptor = Object.getOwnPropertyDescriptor(sentryWrapped, 'name');
    if (descriptor.configurable) {
      Object.defineProperty(sentryWrapped, 'name', {
        get() {
          return fn.name;
        },
      });
    }
  } catch (e3) {
    // This may throw if e.g. the descriptor does not exist, or a browser does not allow redefining `name`.
    // to save some bytes we simply try-catch this
  }

  return sentryWrapped;
}


//# sourceMappingURL=helpers.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/userfeedback.js


/**
 * Creates an envelope from a user feedback.
 */
function createUserFeedbackEnvelope(
  feedback,
  {
    metadata,
    tunnel,
    dsn,
  }

,
) {
  const headers = {
    event_id: feedback.event_id,
    sent_at: new Date().toISOString(),
    ...(metadata &&
      metadata.sdk && {
        sdk: {
          name: metadata.sdk.name,
          version: metadata.sdk.version,
        },
      }),
    ...(!!tunnel && !!dsn && { dsn: dsn_dsnToString(dsn) }),
  };
  const item = createUserFeedbackEnvelopeItem(feedback);

  return envelope_createEnvelope(headers, [item]);
}

function createUserFeedbackEnvelopeItem(feedback) {
  const feedbackHeaders = {
    type: 'user_report',
  };
  return [feedbackHeaders, feedback];
}


//# sourceMappingURL=userfeedback.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/client.js






/**
 * Configuration options for the Sentry Browser SDK.
 * @see @sentry/core Options for more information.
 */

/**
 * The Sentry Browser SDK Client.
 *
 * @see BrowserOptions for documentation on configuration options.
 * @see SentryClient for usage documentation.
 */
class BrowserClient extends BaseClient {
  /**
   * Creates a new Browser SDK instance.
   *
   * @param options Configuration options for this SDK.
   */
   constructor(options) {
    const opts = {
      // We default this to true, as it is the safer scenario
      parentSpanIsAlwaysRootSpan: true,
      ...options,
    };
    const sdkSource = helpers_WINDOW.SENTRY_SDK_SOURCE || getSDKSource();
    applySdkMetadata(opts, 'browser', ['browser'], sdkSource);

    super(opts);

    if (opts.sendClientReports && helpers_WINDOW.document) {
      helpers_WINDOW.document.addEventListener('visibilitychange', () => {
        if (helpers_WINDOW.document.visibilityState === 'hidden') {
          this._flushOutcomes();
        }
      });
    }
  }

  /**
   * @inheritDoc
   */
   eventFromException(exception, hint) {
    return eventFromException(this._options.stackParser, exception, hint, this._options.attachStacktrace);
  }

  /**
   * @inheritDoc
   */
   eventFromMessage(
    message,
    level = 'info',
    hint,
  ) {
    return eventFromMessage(this._options.stackParser, message, level, hint, this._options.attachStacktrace);
  }

  /**
   * Sends user feedback to Sentry.
   *
   * @deprecated Use `captureFeedback` instead.
   */
   captureUserFeedback(feedback) {
    if (!this._isEnabled()) {
      esm_debug_build_DEBUG_BUILD && logger_logger.warn('SDK not enabled, will not capture user feedback.');
      return;
    }

    const envelope = createUserFeedbackEnvelope(feedback, {
      metadata: this.getSdkMetadata(),
      dsn: this.getDsn(),
      tunnel: this.getOptions().tunnel,
    });

    // sendEnvelope should not throw
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    this.sendEnvelope(envelope);
  }

  /**
   * @inheritDoc
   */
   _prepareEvent(event, hint, scope) {
    event.platform = event.platform || 'javascript';
    return super._prepareEvent(event, hint, scope);
  }
}


//# sourceMappingURL=client.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/instrument/handlers.js




// We keep the handlers globally
const handlers = {};
const instrumented = {};

/** Add a handler function. */
function handlers_addHandler(type, handler) {
  handlers[type] = handlers[type] || [];
  (handlers[type] ).push(handler);
}

/**
 * Reset all instrumentation handlers.
 * This can be used by tests to ensure we have a clean slate of instrumentation handlers.
 */
function resetInstrumentationHandlers() {
  Object.keys(handlers).forEach(key => {
    handlers[key ] = undefined;
  });
}

/** Maybe run an instrumentation function, unless it was already called. */
function handlers_maybeInstrument(type, instrumentFn) {
  if (!instrumented[type]) {
    instrumented[type] = true;
    try {
      instrumentFn();
    } catch (e) {
      utils_hoist_debug_build_DEBUG_BUILD && logger_logger.error(`Error while instrumenting ${type}`, e);
    }
  }
}

/** Trigger handlers for a given instrumentation type. */
function handlers_triggerHandlers(type, data) {
  const typeHandlers = type && handlers[type];
  if (!typeHandlers) {
    return;
  }

  for (const handler of typeHandlers) {
    try {
      handler(data);
    } catch (e) {
      utils_hoist_debug_build_DEBUG_BUILD &&
        logger_logger.error(
          `Error while triggering instrumentation handler.\nType: ${type}\nName: ${getFunctionName(handler)}\nError:`,
          e,
        );
    }
  }
}


//# sourceMappingURL=handlers.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry-internal/browser-utils/build/esm/types.js


const types_WINDOW = worldwide_GLOBAL_OBJ

;


//# sourceMappingURL=types.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry-internal/browser-utils/build/esm/instrument/dom.js



const DEBOUNCE_DURATION = 1000;

let debounceTimerID;
let lastCapturedEventType;
let lastCapturedEventTargetId;

/**
 * Add an instrumentation handler for when a click or a keypress happens.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addClickKeypressInstrumentationHandler(handler) {
  const type = 'dom';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, instrumentDOM);
}

/** Exported for tests only. */
function instrumentDOM() {
  if (!types_WINDOW.document) {
    return;
  }

  // Make it so that any click or keypress that is unhandled / bubbled up all the way to the document triggers our dom
  // handlers. (Normally we have only one, which captures a breadcrumb for each click or keypress.) Do this before
  // we instrument `addEventListener` so that we don't end up attaching this handler twice.
  const triggerDOMHandler = handlers_triggerHandlers.bind(null, 'dom');
  const globalDOMEventHandler = makeDOMEventHandler(triggerDOMHandler, true);
  types_WINDOW.document.addEventListener('click', globalDOMEventHandler, false);
  types_WINDOW.document.addEventListener('keypress', globalDOMEventHandler, false);

  // After hooking into click and keypress events bubbled up to `document`, we also hook into user-handled
  // clicks & keypresses, by adding an event listener of our own to any element to which they add a listener. That
  // way, whenever one of their handlers is triggered, ours will be, too. (This is needed because their handler
  // could potentially prevent the event from bubbling up to our global listeners. This way, our handler are still
  // guaranteed to fire at least once.)
  ['EventTarget', 'Node'].forEach((target) => {
    const globalObject = types_WINDOW ;
    const targetObj = globalObject[target];
    const proto = targetObj && targetObj.prototype;

    // eslint-disable-next-line no-prototype-builtins
    if (!proto || !proto.hasOwnProperty || !proto.hasOwnProperty('addEventListener')) {
      return;
    }

    fill(proto, 'addEventListener', function (originalAddEventListener) {
      return function ( type, listener, options) {
        if (type === 'click' || type == 'keypress') {
          try {
            const handlers = (this.__sentry_instrumentation_handlers__ =
              this.__sentry_instrumentation_handlers__ || {});
            const handlerForType = (handlers[type] = handlers[type] || { refCount: 0 });

            if (!handlerForType.handler) {
              const handler = makeDOMEventHandler(triggerDOMHandler);
              handlerForType.handler = handler;
              originalAddEventListener.call(this, type, handler, options);
            }

            handlerForType.refCount++;
          } catch (e) {
            // Accessing dom properties is always fragile.
            // Also allows us to skip `addEventListeners` calls with no proper `this` context.
          }
        }

        return originalAddEventListener.call(this, type, listener, options);
      };
    });

    fill(
      proto,
      'removeEventListener',
      function (originalRemoveEventListener) {
        return function ( type, listener, options) {
          if (type === 'click' || type == 'keypress') {
            try {
              const handlers = this.__sentry_instrumentation_handlers__ || {};
              const handlerForType = handlers[type];

              if (handlerForType) {
                handlerForType.refCount--;
                // If there are no longer any custom handlers of the current type on this element, we can remove ours, too.
                if (handlerForType.refCount <= 0) {
                  originalRemoveEventListener.call(this, type, handlerForType.handler, options);
                  handlerForType.handler = undefined;
                  delete handlers[type]; // eslint-disable-line @typescript-eslint/no-dynamic-delete
                }

                // If there are no longer any custom handlers of any type on this element, cleanup everything.
                if (Object.keys(handlers).length === 0) {
                  delete this.__sentry_instrumentation_handlers__;
                }
              }
            } catch (e) {
              // Accessing dom properties is always fragile.
              // Also allows us to skip `addEventListeners` calls with no proper `this` context.
            }
          }

          return originalRemoveEventListener.call(this, type, listener, options);
        };
      },
    );
  });
}

/**
 * Check whether the event is similar to the last captured one. For example, two click events on the same button.
 */
function isSimilarToLastCapturedEvent(event) {
  // If both events have different type, then user definitely performed two separate actions. e.g. click + keypress.
  if (event.type !== lastCapturedEventType) {
    return false;
  }

  try {
    // If both events have the same type, it's still possible that actions were performed on different targets.
    // e.g. 2 clicks on different buttons.
    if (!event.target || (event.target )._sentryId !== lastCapturedEventTargetId) {
      return false;
    }
  } catch (e) {
    // just accessing `target` property can throw an exception in some rare circumstances
    // see: https://github.com/getsentry/sentry-javascript/issues/838
  }

  // If both events have the same type _and_ same `target` (an element which triggered an event, _not necessarily_
  // to which an event listener was attached), we treat them as the same action, as we want to capture
  // only one breadcrumb. e.g. multiple clicks on the same button, or typing inside a user input box.
  return true;
}

/**
 * Decide whether an event should be captured.
 * @param event event to be captured
 */
function shouldSkipDOMEvent(eventType, target) {
  // We are only interested in filtering `keypress` events for now.
  if (eventType !== 'keypress') {
    return false;
  }

  if (!target || !target.tagName) {
    return true;
  }

  // Only consider keypress events on actual input elements. This will disregard keypresses targeting body
  // e.g.tabbing through elements, hotkeys, etc.
  if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
    return false;
  }

  return true;
}

/**
 * Wraps addEventListener to capture UI breadcrumbs
 */
function makeDOMEventHandler(
  handler,
  globalListener = false,
) {
  return (event) => {
    // It's possible this handler might trigger multiple times for the same
    // event (e.g. event propagation through node ancestors).
    // Ignore if we've already captured that event.
    if (!event || event['_sentryCaptured']) {
      return;
    }

    const target = getEventTarget(event);

    // We always want to skip _some_ events.
    if (shouldSkipDOMEvent(event.type, target)) {
      return;
    }

    // Mark event as "seen"
    object_addNonEnumerableProperty(event, '_sentryCaptured', true);

    if (target && !target._sentryId) {
      // Add UUID to event target so we can identify if
      object_addNonEnumerableProperty(target, '_sentryId', misc_uuid4());
    }

    const name = event.type === 'keypress' ? 'input' : event.type;

    // If there is no last captured event, it means that we can safely capture the new event and store it for future comparisons.
    // If there is a last captured event, see if the new event is different enough to treat it as a unique one.
    // If that's the case, emit the previous event and store locally the newly-captured DOM event.
    if (!isSimilarToLastCapturedEvent(event)) {
      const handlerData = { event, name, global: globalListener };
      handler(handlerData);
      lastCapturedEventType = event.type;
      lastCapturedEventTargetId = target ? target._sentryId : undefined;
    }

    // Start a new debounce timer that will prevent us from capturing multiple events that should be grouped together.
    clearTimeout(debounceTimerID);
    debounceTimerID = types_WINDOW.setTimeout(() => {
      lastCapturedEventTargetId = undefined;
      lastCapturedEventType = undefined;
    }, DEBOUNCE_DURATION);
  };
}

function getEventTarget(event) {
  try {
    return event.target ;
  } catch (e) {
    // just accessing `target` property can throw an exception in some rare circumstances
    // see: https://github.com/getsentry/sentry-javascript/issues/838
    return null;
  }
}


//# sourceMappingURL=dom.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry-internal/browser-utils/build/esm/instrument/xhr.js



const SENTRY_XHR_DATA_KEY = '__sentry_xhr_v3__';

/**
 * Add an instrumentation handler for when an XHR request happens.
 * The handler function is called once when the request starts and once when it ends,
 * which can be identified by checking if it has an `endTimestamp`.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addXhrInstrumentationHandler(handler) {
  const type = 'xhr';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, instrumentXHR);
}

/** Exported only for tests. */
function instrumentXHR() {
  if (!types_WINDOW.XMLHttpRequest) {
    return;
  }

  const xhrproto = XMLHttpRequest.prototype;

  // eslint-disable-next-line @typescript-eslint/unbound-method
  xhrproto.open = new Proxy(xhrproto.open, {
    apply(originalOpen, xhrOpenThisArg, xhrOpenArgArray) {
      // NOTE: If you are a Sentry user, and you are seeing this stack frame,
      //       it means the error, that was caused by your XHR call did not
      //       have a stack trace. If you are using HttpClient integration,
      //       this is the expected behavior, as we are using this virtual error to capture
      //       the location of your XHR call, and group your HttpClient events accordingly.
      const virtualError = new Error();

      const startTimestamp = time_timestampInSeconds() * 1000;

      // open() should always be called with two or more arguments
      // But to be on the safe side, we actually validate this and bail out if we don't have a method & url
      const method = isString(xhrOpenArgArray[0]) ? xhrOpenArgArray[0].toUpperCase() : undefined;
      const url = parseUrl(xhrOpenArgArray[1]);

      if (!method || !url) {
        return originalOpen.apply(xhrOpenThisArg, xhrOpenArgArray);
      }

      xhrOpenThisArg[SENTRY_XHR_DATA_KEY] = {
        method,
        url,
        request_headers: {},
      };

      // if Sentry key appears in URL, don't capture it as a request
      if (method === 'POST' && url.match(/sentry_key/)) {
        xhrOpenThisArg.__sentry_own_request__ = true;
      }

      const onreadystatechangeHandler = () => {
        // For whatever reason, this is not the same instance here as from the outer method
        const xhrInfo = xhrOpenThisArg[SENTRY_XHR_DATA_KEY];

        if (!xhrInfo) {
          return;
        }

        if (xhrOpenThisArg.readyState === 4) {
          try {
            // touching statusCode in some platforms throws
            // an exception
            xhrInfo.status_code = xhrOpenThisArg.status;
          } catch (e) {
            /* do nothing */
          }

          const handlerData = {
            endTimestamp: time_timestampInSeconds() * 1000,
            startTimestamp,
            xhr: xhrOpenThisArg,
            virtualError,
          };
          handlers_triggerHandlers('xhr', handlerData);
        }
      };

      if ('onreadystatechange' in xhrOpenThisArg && typeof xhrOpenThisArg.onreadystatechange === 'function') {
        xhrOpenThisArg.onreadystatechange = new Proxy(xhrOpenThisArg.onreadystatechange, {
          apply(originalOnreadystatechange, onreadystatechangeThisArg, onreadystatechangeArgArray) {
            onreadystatechangeHandler();
            return originalOnreadystatechange.apply(onreadystatechangeThisArg, onreadystatechangeArgArray);
          },
        });
      } else {
        xhrOpenThisArg.addEventListener('readystatechange', onreadystatechangeHandler);
      }

      // Intercepting `setRequestHeader` to access the request headers of XHR instance.
      // This will only work for user/library defined headers, not for the default/browser-assigned headers.
      // Request cookies are also unavailable for XHR, as `Cookie` header can't be defined by `setRequestHeader`.
      xhrOpenThisArg.setRequestHeader = new Proxy(xhrOpenThisArg.setRequestHeader, {
        apply(
          originalSetRequestHeader,
          setRequestHeaderThisArg,
          setRequestHeaderArgArray,
        ) {
          const [header, value] = setRequestHeaderArgArray;

          const xhrInfo = setRequestHeaderThisArg[SENTRY_XHR_DATA_KEY];

          if (xhrInfo && isString(header) && isString(value)) {
            xhrInfo.request_headers[header.toLowerCase()] = value;
          }

          return originalSetRequestHeader.apply(setRequestHeaderThisArg, setRequestHeaderArgArray);
        },
      });

      return originalOpen.apply(xhrOpenThisArg, xhrOpenArgArray);
    },
  });

  // eslint-disable-next-line @typescript-eslint/unbound-method
  xhrproto.send = new Proxy(xhrproto.send, {
    apply(originalSend, sendThisArg, sendArgArray) {
      const sentryXhrData = sendThisArg[SENTRY_XHR_DATA_KEY];

      if (!sentryXhrData) {
        return originalSend.apply(sendThisArg, sendArgArray);
      }

      if (sendArgArray[0] !== undefined) {
        sentryXhrData.body = sendArgArray[0];
      }

      const handlerData = {
        startTimestamp: time_timestampInSeconds() * 1000,
        xhr: sendThisArg,
      };
      handlers_triggerHandlers('xhr', handlerData);

      return originalSend.apply(sendThisArg, sendArgArray);
    },
  });
}

function parseUrl(url) {
  if (isString(url)) {
    return url;
  }

  try {
    // url can be a string or URL
    // but since URL is not available in IE11, we do not check for it,
    // but simply assume it is an URL and return `toString()` from it (which returns the full URL)
    // If that fails, we just return undefined
    return (url ).toString();
  } catch (e2) {} // eslint-disable-line no-empty

  return undefined;
}


//# sourceMappingURL=xhr.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/vendor/supportsHistory.js


// Based on https://github.com/angular/angular.js/pull/13945/files
// The MIT License


const supportsHistory_WINDOW = worldwide_GLOBAL_OBJ ;

/**
 * Tells whether current environment supports History API
 * {@link supportsHistory}.
 *
 * @returns Answer to the given question.
 */
function supportsHistory() {
  // NOTE: in Chrome App environment, touching history.pushState, *even inside
  //       a try/catch block*, will cause Chrome to output an error to console.error
  // borrowed from: https://github.com/angular/angular.js/pull/13945/files
  // TODO(v9): Remove this custom check, it is pretty old and likely not needed anymore
  const chromeVar = (supportsHistory_WINDOW ).chrome;
  const isChromePackagedApp = chromeVar && chromeVar.app && chromeVar.app.runtime;
  const hasHistoryApi = 'history' in supportsHistory_WINDOW && !!supportsHistory_WINDOW.history.pushState && !!supportsHistory_WINDOW.history.replaceState;

  return !isChromePackagedApp && hasHistoryApi;
}


//# sourceMappingURL=supportsHistory.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry-internal/browser-utils/build/esm/instrument/history.js



let lastHref;

/**
 * Add an instrumentation handler for when a fetch request happens.
 * The handler function is called once when the request starts and once when it ends,
 * which can be identified by checking if it has an `endTimestamp`.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addHistoryInstrumentationHandler(handler) {
  const type = 'history';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, instrumentHistory);
}

function instrumentHistory() {
  if (!supportsHistory()) {
    return;
  }

  const oldOnPopState = types_WINDOW.onpopstate;
  types_WINDOW.onpopstate = function ( ...args) {
    const to = types_WINDOW.location.href;
    // keep track of the current URL state, as we always receive only the updated state
    const from = lastHref;
    lastHref = to;
    const handlerData = { from, to };
    handlers_triggerHandlers('history', handlerData);
    if (oldOnPopState) {
      // Apparently this can throw in Firefox when incorrectly implemented plugin is installed.
      // https://github.com/getsentry/sentry-javascript/issues/3344
      // https://github.com/bugsnag/bugsnag-js/issues/469
      try {
        return oldOnPopState.apply(this, args);
      } catch (_oO) {
        // no-empty
      }
    }
  };

  function historyReplacementFunction(originalHistoryFunction) {
    return function ( ...args) {
      const url = args.length > 2 ? args[2] : undefined;
      if (url) {
        // coerce to string (this is what pushState does)
        const from = lastHref;
        const to = String(url);
        // keep track of the current URL state, as we always receive only the updated state
        lastHref = to;
        const handlerData = { from, to };
        handlers_triggerHandlers('history', handlerData);
      }
      return originalHistoryFunction.apply(this, args);
    };
  }

  fill(types_WINDOW.history, 'pushState', historyReplacementFunction);
  fill(types_WINDOW.history, 'replaceState', historyReplacementFunction);
}


//# sourceMappingURL=history.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/instrument/console.js





/**
 * Add an instrumentation handler for when a console.xxx method is called.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addConsoleInstrumentationHandler(handler) {
  const type = 'console';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, instrumentConsole);
}

function instrumentConsole() {
  if (!("console" in worldwide_GLOBAL_OBJ)) {
    return;
  }

  CONSOLE_LEVELS.forEach(function (level) {
    if (!(level in worldwide_GLOBAL_OBJ.console)) {
      return;
    }

    fill(worldwide_GLOBAL_OBJ.console, level, function (originalConsoleMethod) {
      originalConsoleMethods[level] = originalConsoleMethod;

      return function (...args) {
        const handlerData = { args, level };
        handlers_triggerHandlers('console', handlerData);

        const log = originalConsoleMethods[level];
        log && log.apply(worldwide_GLOBAL_OBJ.console, args);
      };
    });
  });
}


//# sourceMappingURL=console.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/instrument/fetch.js







/**
 * Add an instrumentation handler for when a fetch request happens.
 * The handler function is called once when the request starts and once when it ends,
 * which can be identified by checking if it has an `endTimestamp`.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addFetchInstrumentationHandler(
  handler,
  skipNativeFetchCheck,
) {
  const type = 'fetch';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, () => instrumentFetch(undefined, skipNativeFetchCheck));
}

/**
 * Add an instrumentation handler for long-lived fetch requests, like consuming server-sent events (SSE) via fetch.
 * The handler will resolve the request body and emit the actual `endTimestamp`, so that the
 * span can be updated accordingly.
 *
 * Only used internally
 * @hidden
 */
function addFetchEndInstrumentationHandler(handler) {
  const type = 'fetch-body-resolved';
  addHandler(type, handler);
  maybeInstrument(type, () => instrumentFetch(streamHandler));
}

function instrumentFetch(onFetchResolved, skipNativeFetchCheck = false) {
  if (skipNativeFetchCheck && !supportsNativeFetch()) {
    return;
  }

  fill(worldwide_GLOBAL_OBJ, 'fetch', function (originalFetch) {
    return function (...args) {
      // We capture the error right here and not in the Promise error callback because Safari (and probably other
      // browsers too) will wipe the stack trace up to this point, only leaving us with this file which is useless.

      // NOTE: If you are a Sentry user, and you are seeing this stack frame,
      //       it means the error, that was caused by your fetch call did not
      //       have a stack trace, so the SDK backfilled the stack trace so
      //       you can see which fetch call failed.
      const virtualError = new Error();

      const { method, url } = parseFetchArgs(args);
      const handlerData = {
        args,
        fetchData: {
          method,
          url,
        },
        startTimestamp: time_timestampInSeconds() * 1000,
        // // Adding the error to be able to fingerprint the failed fetch event in HttpClient instrumentation
        virtualError,
      };

      // if there is no callback, fetch is instrumented directly
      if (!onFetchResolved) {
        handlers_triggerHandlers('fetch', {
          ...handlerData,
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      return originalFetch.apply(worldwide_GLOBAL_OBJ, args).then(
        async (response) => {
          if (onFetchResolved) {
            onFetchResolved(response);
          } else {
            handlers_triggerHandlers('fetch', {
              ...handlerData,
              endTimestamp: time_timestampInSeconds() * 1000,
              response,
            });
          }

          return response;
        },
        (error) => {
          handlers_triggerHandlers('fetch', {
            ...handlerData,
            endTimestamp: time_timestampInSeconds() * 1000,
            error,
          });

          if (isError(error) && error.stack === undefined) {
            // NOTE: If you are a Sentry user, and you are seeing this stack frame,
            //       it means the error, that was caused by your fetch call did not
            //       have a stack trace, so the SDK backfilled the stack trace so
            //       you can see which fetch call failed.
            error.stack = virtualError.stack;
            object_addNonEnumerableProperty(error, 'framesToPop', 1);
          }

          // NOTE: If you are a Sentry user, and you are seeing this stack frame,
          //       it means the sentry.javascript SDK caught an error invoking your application code.
          //       This is expected behavior and NOT indicative of a bug with sentry.javascript.
          throw error;
        },
      );
    };
  });
}

async function resolveResponse(res, onFinishedResolving) {
  if (res && res.body) {
    const body = res.body;
    const responseReader = body.getReader();

    // Define a maximum duration after which we just cancel
    const maxFetchDurationTimeout = setTimeout(
      () => {
        body.cancel().then(null, () => {
          // noop
        });
      },
      90 * 1000, // 90s
    );

    let readingActive = true;
    while (readingActive) {
      let chunkTimeout;
      try {
        // abort reading if read op takes more than 5s
        chunkTimeout = setTimeout(() => {
          body.cancel().then(null, () => {
            // noop on error
          });
        }, 5000);

        // This .read() call will reject/throw when we abort due to timeouts through `body.cancel()`
        const { done } = await responseReader.read();

        clearTimeout(chunkTimeout);

        if (done) {
          onFinishedResolving();
          readingActive = false;
        }
      } catch (error) {
        readingActive = false;
      } finally {
        clearTimeout(chunkTimeout);
      }
    }

    clearTimeout(maxFetchDurationTimeout);

    responseReader.releaseLock();
    body.cancel().then(null, () => {
      // noop on error
    });
  }
}

function streamHandler(response) {
  // clone response for awaiting stream
  let clonedResponseForResolving;
  try {
    clonedResponseForResolving = response.clone();
  } catch (e) {
    return;
  }

  // eslint-disable-next-line @typescript-eslint/no-floating-promises
  resolveResponse(clonedResponseForResolving, () => {
    triggerHandlers('fetch-body-resolved', {
      endTimestamp: timestampInSeconds() * 1000,
      response,
    });
  });
}

function hasProp(obj, prop) {
  return !!obj && typeof obj === 'object' && !!(obj )[prop];
}

function getUrlFromResource(resource) {
  if (typeof resource === 'string') {
    return resource;
  }

  if (!resource) {
    return '';
  }

  if (hasProp(resource, 'url')) {
    return resource.url;
  }

  if (resource.toString) {
    return resource.toString();
  }

  return '';
}

/**
 * Parses the fetch arguments to find the used Http method and the url of the request.
 * Exported for tests only.
 */
function parseFetchArgs(fetchArgs) {
  if (fetchArgs.length === 0) {
    return { method: 'GET', url: '' };
  }

  if (fetchArgs.length === 2) {
    const [url, options] = fetchArgs ;

    return {
      url: getUrlFromResource(url),
      method: hasProp(options, 'method') ? String(options.method).toUpperCase() : 'GET',
    };
  }

  const arg = fetchArgs[0];
  return {
    url: getUrlFromResource(arg ),
    method: hasProp(arg, 'method') ? String(arg.method).toUpperCase() : 'GET',
  };
}


//# sourceMappingURL=fetch.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/breadcrumbs.js




/**
 * Default maximum number of breadcrumbs added to an event. Can be overwritten
 * with {@link Options.maxBreadcrumbs}.
 */
const DEFAULT_BREADCRUMBS = 100;

/**
 * Records a new breadcrumb which will be attached to future events.
 *
 * Breadcrumbs will be added to subsequent events to provide more context on
 * user's actions prior to an error or crash.
 */
function addBreadcrumb(breadcrumb, hint) {
  const client = currentScopes_getClient();
  const isolationScope = currentScopes_getIsolationScope();

  if (!client) return;

  const { beforeBreadcrumb = null, maxBreadcrumbs = DEFAULT_BREADCRUMBS } = client.getOptions();

  if (maxBreadcrumbs <= 0) return;

  const timestamp = dateTimestampInSeconds();
  const mergedBreadcrumb = { timestamp, ...breadcrumb };
  const finalBreadcrumb = beforeBreadcrumb
    ? (consoleSandbox(() => beforeBreadcrumb(mergedBreadcrumb, hint)) )
    : mergedBreadcrumb;

  if (finalBreadcrumb === null) return;

  if (client.emit) {
    client.emit('beforeAddBreadcrumb', finalBreadcrumb, hint);
  }

  isolationScope.addBreadcrumb(finalBreadcrumb, maxBreadcrumbs);
}


//# sourceMappingURL=breadcrumbs.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/severity.js
/**
 * @deprecated This variable has been deprecated and will be removed in the next major version.
 */
const validSeverityLevels = (/* unused pure expression or super */ null && (['fatal', 'error', 'warning', 'log', 'info', 'debug']));

/**
 * Converts a string-based level into a `SeverityLevel`, normalizing it along the way.
 *
 * @param level String representation of desired `SeverityLevel`.
 * @returns The `SeverityLevel` corresponding to the given string, or 'log' if the string isn't a valid level.
 */
function severityLevelFromString(level) {
  return (
    level === 'warn' ? 'warning' : ['fatal', 'error', 'warning', 'log', 'info', 'debug'].includes(level) ? level : 'log'
  ) ;
}


//# sourceMappingURL=severity.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/breadcrumb-log-level.js
/**
 * Determine a breadcrumb's log level (only `warning` or `error`) based on an HTTP status code.
 */
function getBreadcrumbLogLevelFromHttpStatusCode(statusCode) {
  // NOTE: undefined defaults to 'info' in Sentry
  if (statusCode === undefined) {
    return undefined;
  } else if (statusCode >= 400 && statusCode < 500) {
    return 'warning';
  } else if (statusCode >= 500) {
    return 'error';
  } else {
    return undefined;
  }
}


//# sourceMappingURL=breadcrumb-log-level.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/url.js
/**
 * Parses string form of URL into an object
 * // borrowed from https://tools.ietf.org/html/rfc3986#appendix-B
 * // intentionally using regex and not <a/> href parsing trick because React Native and other
 * // environments where DOM might not be available
 * @returns parsed URL object
 */
function url_parseUrl(url) {
  if (!url) {
    return {};
  }

  const match = url.match(/^(([^:/?#]+):)?(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$/);

  if (!match) {
    return {};
  }

  // coerce to undefined values to empty string so we don't get 'undefined'
  const query = match[6] || '';
  const fragment = match[8] || '';
  return {
    host: match[4],
    path: match[5],
    protocol: match[2],
    search: query,
    hash: fragment,
    relative: match[5] + query + fragment, // everything minus origin
  };
}

/**
 * Strip the query string and fragment off of a given URL or path (if present)
 *
 * @param urlPath Full URL or path, including possible query string and/or fragment
 * @returns URL or path without query string or fragment
 */
function stripUrlQueryAndFragment(urlPath) {
  return (urlPath.split(/[?#]/, 1) )[0];
}

/**
 * Returns number of URL segments of a passed string URL.
 *
 * @deprecated This function will be removed in the next major version.
 */
// TODO(v9): Hoist this function into the places where we use it. (as it stands only react router v6 instrumentation)
function getNumberOfUrlSegments(url) {
  // split at '/' or at '\/' to split regex urls correctly
  return url.split(/\\?\//).filter(s => s.length > 0 && s !== ',').length;
}

/**
 * Takes a URL object and returns a sanitized string which is safe to use as span name
 * see: https://develop.sentry.dev/sdk/data-handling/#structuring-data
 */
function getSanitizedUrlString(url) {
  const { protocol, host, path } = url;

  const filteredHost =
    (host &&
      host
        // Always filter out authority
        .replace(/^.*@/, '[filtered]:[filtered]@')
        // Don't show standard :80 (http) and :443 (https) ports to reduce the noise
        // TODO: Use new URL global if it exists
        .replace(/(:80)$/, '')
        .replace(/(:443)$/, '')) ||
    '';

  return `${protocol ? `${protocol}://` : ''}${filteredHost}${path}`;
}


//# sourceMappingURL=url.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/integrations/breadcrumbs.js





/* eslint-disable max-lines */


/** maxStringLength gets capped to prevent 100 breadcrumbs exceeding 1MB event payload size */
const MAX_ALLOWED_STRING_LENGTH = 1024;

const breadcrumbs_INTEGRATION_NAME = 'Breadcrumbs';

const _breadcrumbsIntegration = ((options = {}) => {
  const _options = {
    console: true,
    dom: true,
    fetch: true,
    history: true,
    sentry: true,
    xhr: true,
    ...options,
  };

  return {
    name: breadcrumbs_INTEGRATION_NAME,
    setup(client) {
      if (_options.console) {
        addConsoleInstrumentationHandler(_getConsoleBreadcrumbHandler(client));
      }
      if (_options.dom) {
        addClickKeypressInstrumentationHandler(_getDomBreadcrumbHandler(client, _options.dom));
      }
      if (_options.xhr) {
        addXhrInstrumentationHandler(_getXhrBreadcrumbHandler(client));
      }
      if (_options.fetch) {
        addFetchInstrumentationHandler(_getFetchBreadcrumbHandler(client));
      }
      if (_options.history) {
        addHistoryInstrumentationHandler(_getHistoryBreadcrumbHandler(client));
      }
      if (_options.sentry) {
        client.on('beforeSendEvent', _getSentryBreadcrumbHandler(client));
      }
    },
  };
}) ;

const breadcrumbsIntegration = defineIntegration(_breadcrumbsIntegration);

/**
 * Adds a breadcrumb for Sentry events or transactions if this option is enabled.
 */
function _getSentryBreadcrumbHandler(client) {
  return function addSentryBreadcrumb(event) {
    if (currentScopes_getClient() !== client) {
      return;
    }

    addBreadcrumb(
      {
        category: `sentry.${event.type === 'transaction' ? 'transaction' : 'event'}`,
        event_id: event.event_id,
        level: event.level,
        message: getEventDescription(event),
      },
      {
        event,
      },
    );
  };
}

/**
 * A HOC that creates a function that creates breadcrumbs from DOM API calls.
 * This is a HOC so that we get access to dom options in the closure.
 */
function _getDomBreadcrumbHandler(
  client,
  dom,
) {
  return function _innerDomBreadcrumb(handlerData) {
    if (currentScopes_getClient() !== client) {
      return;
    }

    let target;
    let componentName;
    let keyAttrs = typeof dom === 'object' ? dom.serializeAttribute : undefined;

    let maxStringLength =
      typeof dom === 'object' && typeof dom.maxStringLength === 'number' ? dom.maxStringLength : undefined;
    if (maxStringLength && maxStringLength > MAX_ALLOWED_STRING_LENGTH) {
      esm_debug_build_DEBUG_BUILD &&
        logger_logger.warn(
          `\`dom.maxStringLength\` cannot exceed ${MAX_ALLOWED_STRING_LENGTH}, but a value of ${maxStringLength} was configured. Sentry will use ${MAX_ALLOWED_STRING_LENGTH} instead.`,
        );
      maxStringLength = MAX_ALLOWED_STRING_LENGTH;
    }

    if (typeof keyAttrs === 'string') {
      keyAttrs = [keyAttrs];
    }

    // Accessing event.target can throw (see getsentry/raven-js#838, #768)
    try {
      const event = handlerData.event ;
      const element = _isEvent(event) ? event.target : event;

      target = htmlTreeAsString(element, { keyAttrs, maxStringLength });
      componentName = getComponentName(element);
    } catch (e) {
      target = '<unknown>';
    }

    if (target.length === 0) {
      return;
    }

    const breadcrumb = {
      category: `ui.${handlerData.name}`,
      message: target,
    };

    if (componentName) {
      breadcrumb.data = { 'ui.component_name': componentName };
    }

    addBreadcrumb(breadcrumb, {
      event: handlerData.event,
      name: handlerData.name,
      global: handlerData.global,
    });
  };
}

/**
 * Creates breadcrumbs from console API calls
 */
function _getConsoleBreadcrumbHandler(client) {
  return function _consoleBreadcrumb(handlerData) {
    if (currentScopes_getClient() !== client) {
      return;
    }

    const breadcrumb = {
      category: 'console',
      data: {
        arguments: handlerData.args,
        logger: 'console',
      },
      level: severityLevelFromString(handlerData.level),
      message: safeJoin(handlerData.args, ' '),
    };

    if (handlerData.level === 'assert') {
      if (handlerData.args[0] === false) {
        breadcrumb.message = `Assertion failed: ${safeJoin(handlerData.args.slice(1), ' ') || 'console.assert'}`;
        breadcrumb.data.arguments = handlerData.args.slice(1);
      } else {
        // Don't capture a breadcrumb for passed assertions
        return;
      }
    }

    addBreadcrumb(breadcrumb, {
      input: handlerData.args,
      level: handlerData.level,
    });
  };
}

/**
 * Creates breadcrumbs from XHR API calls
 */
function _getXhrBreadcrumbHandler(client) {
  return function _xhrBreadcrumb(handlerData) {
    if (currentScopes_getClient() !== client) {
      return;
    }

    const { startTimestamp, endTimestamp } = handlerData;

    const sentryXhrData = handlerData.xhr[SENTRY_XHR_DATA_KEY];

    // We only capture complete, non-sentry requests
    if (!startTimestamp || !endTimestamp || !sentryXhrData) {
      return;
    }

    const { method, url, status_code, body } = sentryXhrData;

    const data = {
      method,
      url,
      status_code,
    };

    const hint = {
      xhr: handlerData.xhr,
      input: body,
      startTimestamp,
      endTimestamp,
    };

    const level = getBreadcrumbLogLevelFromHttpStatusCode(status_code);

    addBreadcrumb(
      {
        category: 'xhr',
        data,
        type: 'http',
        level,
      },
      hint,
    );
  };
}

/**
 * Creates breadcrumbs from fetch API calls
 */
function _getFetchBreadcrumbHandler(client) {
  return function _fetchBreadcrumb(handlerData) {
    if (currentScopes_getClient() !== client) {
      return;
    }

    const { startTimestamp, endTimestamp } = handlerData;

    // We only capture complete fetch requests
    if (!endTimestamp) {
      return;
    }

    if (handlerData.fetchData.url.match(/sentry_key/) && handlerData.fetchData.method === 'POST') {
      // We will not create breadcrumbs for fetch requests that contain `sentry_key` (internal sentry requests)
      return;
    }

    if (handlerData.error) {
      const data = handlerData.fetchData;
      const hint = {
        data: handlerData.error,
        input: handlerData.args,
        startTimestamp,
        endTimestamp,
      };

      addBreadcrumb(
        {
          category: 'fetch',
          data,
          level: 'error',
          type: 'http',
        },
        hint,
      );
    } else {
      const response = handlerData.response ;
      const data = {
        ...handlerData.fetchData,
        status_code: response && response.status,
      };
      const hint = {
        input: handlerData.args,
        response,
        startTimestamp,
        endTimestamp,
      };
      const level = getBreadcrumbLogLevelFromHttpStatusCode(data.status_code);

      addBreadcrumb(
        {
          category: 'fetch',
          data,
          type: 'http',
          level,
        },
        hint,
      );
    }
  };
}

/**
 * Creates breadcrumbs from history API calls
 */
function _getHistoryBreadcrumbHandler(client) {
  return function _historyBreadcrumb(handlerData) {
    if (currentScopes_getClient() !== client) {
      return;
    }

    let from = handlerData.from;
    let to = handlerData.to;
    const parsedLoc = url_parseUrl(helpers_WINDOW.location.href);
    let parsedFrom = from ? url_parseUrl(from) : undefined;
    const parsedTo = url_parseUrl(to);

    // Initial pushState doesn't provide `from` information
    if (!parsedFrom || !parsedFrom.path) {
      parsedFrom = parsedLoc;
    }

    // Use only the path component of the URL if the URL matches the current
    // document (almost all the time when using pushState)
    if (parsedLoc.protocol === parsedTo.protocol && parsedLoc.host === parsedTo.host) {
      to = parsedTo.relative;
    }
    if (parsedLoc.protocol === parsedFrom.protocol && parsedLoc.host === parsedFrom.host) {
      from = parsedFrom.relative;
    }

    addBreadcrumb({
      category: 'navigation',
      data: {
        from,
        to,
      },
    });
  };
}

function _isEvent(event) {
  return !!event && !!(event ).target;
}


//# sourceMappingURL=breadcrumbs.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/integrations/browserapierrors.js



const DEFAULT_EVENT_TARGET = [
  'EventTarget',
  'Window',
  'Node',
  'ApplicationCache',
  'AudioTrackList',
  'BroadcastChannel',
  'ChannelMergerNode',
  'CryptoOperation',
  'EventSource',
  'FileReader',
  'HTMLUnknownElement',
  'IDBDatabase',
  'IDBRequest',
  'IDBTransaction',
  'KeyOperation',
  'MediaController',
  'MessagePort',
  'ModalWindow',
  'Notification',
  'SVGElementInstance',
  'Screen',
  'SharedWorker',
  'TextTrack',
  'TextTrackCue',
  'TextTrackList',
  'WebSocket',
  'WebSocketWorker',
  'Worker',
  'XMLHttpRequest',
  'XMLHttpRequestEventTarget',
  'XMLHttpRequestUpload',
];

const browserapierrors_INTEGRATION_NAME = 'BrowserApiErrors';

const _browserApiErrorsIntegration = ((options = {}) => {
  const _options = {
    XMLHttpRequest: true,
    eventTarget: true,
    requestAnimationFrame: true,
    setInterval: true,
    setTimeout: true,
    ...options,
  };

  return {
    name: browserapierrors_INTEGRATION_NAME,
    // TODO: This currently only works for the first client this is setup
    // We may want to adjust this to check for client etc.
    setupOnce() {
      if (_options.setTimeout) {
        fill(helpers_WINDOW, 'setTimeout', _wrapTimeFunction);
      }

      if (_options.setInterval) {
        fill(helpers_WINDOW, 'setInterval', _wrapTimeFunction);
      }

      if (_options.requestAnimationFrame) {
        fill(helpers_WINDOW, 'requestAnimationFrame', _wrapRAF);
      }

      if (_options.XMLHttpRequest && "XMLHttpRequest" in helpers_WINDOW) {
        fill(XMLHttpRequest.prototype, 'send', _wrapXHR);
      }

      const eventTargetOption = _options.eventTarget;
      if (eventTargetOption) {
        const eventTarget = Array.isArray(eventTargetOption) ? eventTargetOption : DEFAULT_EVENT_TARGET;
        eventTarget.forEach(_wrapEventTarget);
      }
    },
  };
}) ;

/**
 * Wrap timer functions and event targets to catch errors and provide better meta data.
 */
const browserApiErrorsIntegration = defineIntegration(_browserApiErrorsIntegration);

function _wrapTimeFunction(original) {
  return function ( ...args) {
    const originalCallback = args[0];
    args[0] = wrap(originalCallback, {
      mechanism: {
        data: { function: getFunctionName(original) },
        handled: false,
        type: 'instrument',
      },
    });
    return original.apply(this, args);
  };
}

function _wrapRAF(original) {
  return function ( callback) {
    return original.apply(this, [
      wrap(callback, {
        mechanism: {
          data: {
            function: 'requestAnimationFrame',
            handler: getFunctionName(original),
          },
          handled: false,
          type: 'instrument',
        },
      }),
    ]);
  };
}

function _wrapXHR(originalSend) {
  return function ( ...args) {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const xhr = this;
    const xmlHttpRequestProps = ['onload', 'onerror', 'onprogress', 'onreadystatechange'];

    xmlHttpRequestProps.forEach(prop => {
      if (prop in xhr && typeof xhr[prop] === 'function') {
        fill(xhr, prop, function (original) {
          const wrapOptions = {
            mechanism: {
              data: {
                function: prop,
                handler: getFunctionName(original),
              },
              handled: false,
              type: 'instrument',
            },
          };

          // If Instrument integration has been called before BrowserApiErrors, get the name of original function
          const originalFunction = getOriginalFunction(original);
          if (originalFunction) {
            wrapOptions.mechanism.data.handler = getFunctionName(originalFunction);
          }

          // Otherwise wrap directly
          return wrap(original, wrapOptions);
        });
      }
    });

    return originalSend.apply(this, args);
  };
}

function _wrapEventTarget(target) {
  const globalObject = helpers_WINDOW ;
  const targetObj = globalObject[target];
  const proto = targetObj && targetObj.prototype;

  // eslint-disable-next-line no-prototype-builtins
  if (!proto || !proto.hasOwnProperty || !proto.hasOwnProperty('addEventListener')) {
    return;
  }

  fill(proto, 'addEventListener', function (original)

 {
    return function ( eventName, fn, options) {
      try {
        if (isEventListenerObject(fn)) {
          // ESlint disable explanation:
          //  First, it is generally safe to call `wrap` with an unbound function. Furthermore, using `.bind()` would
          //  introduce a bug here, because bind returns a new function that doesn't have our
          //  flags(like __sentry_original__) attached. `wrap` checks for those flags to avoid unnecessary wrapping.
          //  Without those flags, every call to addEventListener wraps the function again, causing a memory leak.
          // eslint-disable-next-line @typescript-eslint/unbound-method
          fn.handleEvent = wrap(fn.handleEvent, {
            mechanism: {
              data: {
                function: 'handleEvent',
                handler: getFunctionName(fn),
                target,
              },
              handled: false,
              type: 'instrument',
            },
          });
        }
      } catch (e2) {
        // can sometimes get 'Permission denied to access property "handle Event'
      }

      return original.apply(this, [
        eventName,
        wrap(fn, {
          mechanism: {
            data: {
              function: 'addEventListener',
              handler: getFunctionName(fn),
              target,
            },
            handled: false,
            type: 'instrument',
          },
        }),
        options,
      ]);
    };
  });

  fill(proto, 'removeEventListener', function (originalRemoveEventListener)

 {
    return function ( eventName, fn, options) {
      /**
       * There are 2 possible scenarios here:
       *
       * 1. Someone passes a callback, which was attached prior to Sentry initialization, or by using unmodified
       * method, eg. `document.addEventListener.call(el, name, handler). In this case, we treat this function
       * as a pass-through, and call original `removeEventListener` with it.
       *
       * 2. Someone passes a callback, which was attached after Sentry was initialized, which means that it was using
       * our wrapped version of `addEventListener`, which internally calls `wrap` helper.
       * This helper "wraps" whole callback inside a try/catch statement, and attached appropriate metadata to it,
       * in order for us to make a distinction between wrapped/non-wrapped functions possible.
       * If a function was wrapped, it has additional property of `__sentry_wrapped__`, holding the handler.
       *
       * When someone adds a handler prior to initialization, and then do it again, but after,
       * then we have to detach both of them. Otherwise, if we'd detach only wrapped one, it'd be impossible
       * to get rid of the initial handler and it'd stick there forever.
       */
      try {
        const originalEventHandler = (fn ).__sentry_wrapped__;
        if (originalEventHandler) {
          originalRemoveEventListener.call(this, eventName, originalEventHandler, options);
        }
      } catch (e) {
        // ignore, accessing __sentry_wrapped__ will throw in some Selenium environments
      }
      return originalRemoveEventListener.call(this, eventName, fn, options);
    };
  });
}

function isEventListenerObject(obj) {
  return typeof (obj ).handleEvent === 'function';
}


//# sourceMappingURL=browserapierrors.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/integrations/browsersession.js





/**
 * When added, automatically creates sessions which allow you to track adoption and crashes (crash free rate) in your Releases in Sentry.
 * More information: https://docs.sentry.io/product/releases/health/
 *
 * Note: In order for session tracking to work, you need to set up Releases: https://docs.sentry.io/product/releases/
 */
const browserSessionIntegration = defineIntegration(() => {
  return {
    name: 'BrowserSession',
    setupOnce() {
      if (typeof helpers_WINDOW.document === 'undefined') {
        esm_debug_build_DEBUG_BUILD &&
          logger_logger.warn('Using the `browserSessionIntegration` in non-browser environments is not supported.');
        return;
      }

      // The session duration for browser sessions does not track a meaningful
      // concept that can be used as a metric.
      // Automatically captured sessions are akin to page views, and thus we
      // discard their duration.
      startSession({ ignoreDuration: true });
      captureSession();

      // We want to create a session for every navigation as well
      addHistoryInstrumentationHandler(({ from, to }) => {
        // Don't create an additional session for the initial route or if the location did not change
        if (from !== undefined && from !== to) {
          startSession({ ignoreDuration: true });
          captureSession();
        }
      });
    },
  };
});


//# sourceMappingURL=browsersession.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/instrument/globalError.js



let _oldOnErrorHandler = null;

/**
 * Add an instrumentation handler for when an error is captured by the global error handler.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addGlobalErrorInstrumentationHandler(handler) {
  const type = 'error';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, instrumentError);
}

function instrumentError() {
  _oldOnErrorHandler = worldwide_GLOBAL_OBJ.onerror;

  // Note: The reason we are doing window.onerror instead of window.addEventListener('error')
  // is that we are using this handler in the Loader Script, to handle buffered errors consistently
  worldwide_GLOBAL_OBJ.onerror = function (
    msg,
    url,
    line,
    column,
    error,
  ) {
    const handlerData = {
      column,
      error,
      line,
      msg,
      url,
    };
    handlers_triggerHandlers('error', handlerData);

    if (_oldOnErrorHandler) {
      // eslint-disable-next-line prefer-rest-params
      return _oldOnErrorHandler.apply(this, arguments);
    }

    return false;
  };

  worldwide_GLOBAL_OBJ.onerror.__SENTRY_INSTRUMENTED__ = true;
}


//# sourceMappingURL=globalError.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/instrument/globalUnhandledRejection.js



let _oldOnUnhandledRejectionHandler = null;

/**
 * Add an instrumentation handler for when an unhandled promise rejection is captured.
 *
 * Use at your own risk, this might break without changelog notice, only used internally.
 * @hidden
 */
function addGlobalUnhandledRejectionInstrumentationHandler(
  handler,
) {
  const type = 'unhandledrejection';
  handlers_addHandler(type, handler);
  handlers_maybeInstrument(type, instrumentUnhandledRejection);
}

function instrumentUnhandledRejection() {
  _oldOnUnhandledRejectionHandler = worldwide_GLOBAL_OBJ.onunhandledrejection;

  // Note: The reason we are doing window.onunhandledrejection instead of window.addEventListener('unhandledrejection')
  // is that we are using this handler in the Loader Script, to handle buffered rejections consistently
  worldwide_GLOBAL_OBJ.onunhandledrejection = function (e) {
    const handlerData = e;
    handlers_triggerHandlers('unhandledrejection', handlerData);

    if (_oldOnUnhandledRejectionHandler) {
      // eslint-disable-next-line prefer-rest-params
      return _oldOnUnhandledRejectionHandler.apply(this, arguments);
    }

    return true;
  };

  worldwide_GLOBAL_OBJ.onunhandledrejection.__SENTRY_INSTRUMENTED__ = true;
}


//# sourceMappingURL=globalUnhandledRejection.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/integrations/globalhandlers.js





const globalhandlers_INTEGRATION_NAME = 'GlobalHandlers';

const _globalHandlersIntegration = ((options = {}) => {
  const _options = {
    onerror: true,
    onunhandledrejection: true,
    ...options,
  };

  return {
    name: globalhandlers_INTEGRATION_NAME,
    setupOnce() {
      Error.stackTraceLimit = 50;
    },
    setup(client) {
      if (_options.onerror) {
        _installGlobalOnErrorHandler(client);
        globalHandlerLog('onerror');
      }
      if (_options.onunhandledrejection) {
        _installGlobalOnUnhandledRejectionHandler(client);
        globalHandlerLog('onunhandledrejection');
      }
    },
  };
}) ;

const globalHandlersIntegration = defineIntegration(_globalHandlersIntegration);

function _installGlobalOnErrorHandler(client) {
  addGlobalErrorInstrumentationHandler(data => {
    const { stackParser, attachStacktrace } = getOptions();

    if (currentScopes_getClient() !== client || shouldIgnoreOnError()) {
      return;
    }

    const { msg, url, line, column, error } = data;

    const event = _enhanceEventWithInitialFrame(
      eventFromUnknownInput(stackParser, error || msg, undefined, attachStacktrace, false),
      url,
      line,
      column,
    );

    event.level = 'error';

    captureEvent(event, {
      originalException: error,
      mechanism: {
        handled: false,
        type: 'onerror',
      },
    });
  });
}

function _installGlobalOnUnhandledRejectionHandler(client) {
  addGlobalUnhandledRejectionInstrumentationHandler(e => {
    const { stackParser, attachStacktrace } = getOptions();

    if (currentScopes_getClient() !== client || shouldIgnoreOnError()) {
      return;
    }

    const error = _getUnhandledRejectionError(e );

    const event = is_isPrimitive(error)
      ? _eventFromRejectionWithPrimitive(error)
      : eventFromUnknownInput(stackParser, error, undefined, attachStacktrace, true);

    event.level = 'error';

    captureEvent(event, {
      originalException: error,
      mechanism: {
        handled: false,
        type: 'onunhandledrejection',
      },
    });
  });
}

function _getUnhandledRejectionError(error) {
  if (is_isPrimitive(error)) {
    return error;
  }

  // dig the object of the rejection out of known event types
  try {

    // PromiseRejectionEvents store the object of the rejection under 'reason'
    // see https://developer.mozilla.org/en-US/docs/Web/API/PromiseRejectionEvent
    if ('reason' in (error )) {
      return (error ).reason;
    }

    // something, somewhere, (likely a browser extension) effectively casts PromiseRejectionEvents
    // to CustomEvents, moving the `promise` and `reason` attributes of the PRE into
    // the CustomEvent's `detail` attribute, since they're not part of CustomEvent's spec
    // see https://developer.mozilla.org/en-US/docs/Web/API/CustomEvent and
    // https://github.com/getsentry/sentry-javascript/issues/2380
    if ('detail' in (error ) && 'reason' in (error ).detail) {
      return (error ).detail.reason;
    }
  } catch (e2) {} // eslint-disable-line no-empty

  return error;
}

/**
 * Create an event from a promise rejection where the `reason` is a primitive.
 *
 * @param reason: The `reason` property of the promise rejection
 * @returns An Event object with an appropriate `exception` value
 */
function _eventFromRejectionWithPrimitive(reason) {
  return {
    exception: {
      values: [
        {
          type: 'UnhandledRejection',
          // String() is needed because the Primitive type includes symbols (which can't be automatically stringified)
          value: `Non-Error promise rejection captured with value: ${String(reason)}`,
        },
      ],
    },
  };
}

function _enhanceEventWithInitialFrame(
  event,
  url,
  line,
  column,
) {
  // event.exception
  const e = (event.exception = event.exception || {});
  // event.exception.values
  const ev = (e.values = e.values || []);
  // event.exception.values[0]
  const ev0 = (ev[0] = ev[0] || {});
  // event.exception.values[0].stacktrace
  const ev0s = (ev0.stacktrace = ev0.stacktrace || {});
  // event.exception.values[0].stacktrace.frames
  const ev0sf = (ev0s.frames = ev0s.frames || []);

  const colno = column;
  const lineno = line;
  const filename = isString(url) && url.length > 0 ? url : getLocationHref();

  // event.exception.values[0].stacktrace.frames
  if (ev0sf.length === 0) {
    ev0sf.push({
      colno,
      filename,
      function: UNKNOWN_FUNCTION,
      in_app: true,
      lineno,
    });
  }

  return event;
}

function globalHandlerLog(type) {
  esm_debug_build_DEBUG_BUILD && logger_logger.log(`Global Handler attached: ${type}`);
}

function getOptions() {
  const client = currentScopes_getClient();
  const options = (client && client.getOptions()) || {
    stackParser: () => [],
    attachStacktrace: false,
  };
  return options;
}


//# sourceMappingURL=globalhandlers.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/integrations/httpcontext.js



/**
 * Collects information about HTTP request headers and
 * attaches them to the event.
 */
const httpContextIntegration = defineIntegration(() => {
  return {
    name: 'HttpContext',
    preprocessEvent(event) {
      // if none of the information we want exists, don't bother
      if (!helpers_WINDOW.navigator && !helpers_WINDOW.location && !helpers_WINDOW.document) {
        return;
      }

      // grab as much info as exists and add it to the event
      const url = (event.request && event.request.url) || (helpers_WINDOW.location && helpers_WINDOW.location.href);
      const { referrer } = helpers_WINDOW.document || {};
      const { userAgent } = helpers_WINDOW.navigator || {};

      const headers = {
        ...(event.request && event.request.headers),
        ...(referrer && { Referer: referrer }),
        ...(userAgent && { 'User-Agent': userAgent }),
      };
      const request = { ...event.request, ...(url && { url }), headers };

      event.request = request;
    },
  };
});


//# sourceMappingURL=httpcontext.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/aggregate-errors.js



/**
 * Creates exceptions inside `event.exception.values` for errors that are nested on properties based on the `key` parameter.
 */
function applyAggregateErrorsToEvent(
  exceptionFromErrorImplementation,
  parser,
  maxValueLimit = 250,
  key,
  limit,
  event,
  hint,
) {
  if (!event.exception || !event.exception.values || !hint || !isInstanceOf(hint.originalException, Error)) {
    return;
  }

  // Generally speaking the last item in `event.exception.values` is the exception originating from the original Error
  const originalException =
    event.exception.values.length > 0 ? event.exception.values[event.exception.values.length - 1] : undefined;

  // We only create exception grouping if there is an exception in the event.
  if (originalException) {
    event.exception.values = truncateAggregateExceptions(
      aggregateExceptionsFromError(
        exceptionFromErrorImplementation,
        parser,
        limit,
        hint.originalException ,
        key,
        event.exception.values,
        originalException,
        0,
      ),
      maxValueLimit,
    );
  }
}

function aggregateExceptionsFromError(
  exceptionFromErrorImplementation,
  parser,
  limit,
  error,
  key,
  prevExceptions,
  exception,
  exceptionId,
) {
  if (prevExceptions.length >= limit + 1) {
    return prevExceptions;
  }

  let newExceptions = [...prevExceptions];

  // Recursively call this function in order to walk down a chain of errors
  if (isInstanceOf(error[key], Error)) {
    applyExceptionGroupFieldsForParentException(exception, exceptionId);
    const newException = exceptionFromErrorImplementation(parser, error[key]);
    const newExceptionId = newExceptions.length;
    applyExceptionGroupFieldsForChildException(newException, key, newExceptionId, exceptionId);
    newExceptions = aggregateExceptionsFromError(
      exceptionFromErrorImplementation,
      parser,
      limit,
      error[key],
      key,
      [newException, ...newExceptions],
      newException,
      newExceptionId,
    );
  }

  // This will create exception grouping for AggregateErrors
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/AggregateError
  if (Array.isArray(error.errors)) {
    error.errors.forEach((childError, i) => {
      if (isInstanceOf(childError, Error)) {
        applyExceptionGroupFieldsForParentException(exception, exceptionId);
        const newException = exceptionFromErrorImplementation(parser, childError);
        const newExceptionId = newExceptions.length;
        applyExceptionGroupFieldsForChildException(newException, `errors[${i}]`, newExceptionId, exceptionId);
        newExceptions = aggregateExceptionsFromError(
          exceptionFromErrorImplementation,
          parser,
          limit,
          childError,
          key,
          [newException, ...newExceptions],
          newException,
          newExceptionId,
        );
      }
    });
  }

  return newExceptions;
}

function applyExceptionGroupFieldsForParentException(exception, exceptionId) {
  // Don't know if this default makes sense. The protocol requires us to set these values so we pick *some* default.
  exception.mechanism = exception.mechanism || { type: 'generic', handled: true };

  exception.mechanism = {
    ...exception.mechanism,
    ...(exception.type === 'AggregateError' && { is_exception_group: true }),
    exception_id: exceptionId,
  };
}

function applyExceptionGroupFieldsForChildException(
  exception,
  source,
  exceptionId,
  parentId,
) {
  // Don't know if this default makes sense. The protocol requires us to set these values so we pick *some* default.
  exception.mechanism = exception.mechanism || { type: 'generic', handled: true };

  exception.mechanism = {
    ...exception.mechanism,
    type: 'chained',
    source,
    exception_id: exceptionId,
    parent_id: parentId,
  };
}

/**
 * Truncate the message (exception.value) of all exceptions in the event.
 * Because this event processor is ran after `applyClientOptions`,
 * we need to truncate the message of the added exceptions here.
 */
function truncateAggregateExceptions(exceptions, maxValueLength) {
  return exceptions.map(exception => {
    if (exception.value) {
      exception.value = truncate(exception.value, maxValueLength);
    }
    return exception;
  });
}


//# sourceMappingURL=aggregate-errors.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/integrations/linkederrors.js



const DEFAULT_KEY = 'cause';
const DEFAULT_LIMIT = 5;

const linkederrors_INTEGRATION_NAME = 'LinkedErrors';

const _linkedErrorsIntegration = ((options = {}) => {
  const limit = options.limit || DEFAULT_LIMIT;
  const key = options.key || DEFAULT_KEY;

  return {
    name: linkederrors_INTEGRATION_NAME,
    preprocessEvent(event, hint, client) {
      const options = client.getOptions();

      applyAggregateErrorsToEvent(
        // This differs from the LinkedErrors integration in core by using a different exceptionFromError function
        exceptionFromError,
        options.stackParser,
        options.maxValueLength,
        key,
        limit,
        event,
        hint,
      );
    },
  };
}) ;

/**
 * Aggregrate linked errors in an event.
 */
const linkedErrorsIntegration = defineIntegration(_linkedErrorsIntegration);


//# sourceMappingURL=linkederrors.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/stack-parsers.js


// This was originally forked from https://github.com/csnover/TraceKit, and was largely
// re - written as part of raven - js.
//
// This code was later copied to the JavaScript mono - repo and further modified and
// refactored over the years.


const OPERA10_PRIORITY = 10;
const OPERA11_PRIORITY = 20;
const CHROME_PRIORITY = 30;
const WINJS_PRIORITY = 40;
const GECKO_PRIORITY = 50;

function createFrame(filename, func, lineno, colno) {
  const frame = {
    filename,
    function: func === '<anonymous>' ? UNKNOWN_FUNCTION : func,
    in_app: true, // All browser frames are considered in_app
  };

  if (lineno !== undefined) {
    frame.lineno = lineno;
  }

  if (colno !== undefined) {
    frame.colno = colno;
  }

  return frame;
}

// This regex matches frames that have no function name (ie. are at the top level of a module).
// For example "at http://localhost:5000//script.js:1:126"
// Frames _with_ function names usually look as follows: "at commitLayoutEffects (react-dom.development.js:23426:1)"
const chromeRegexNoFnName = /^\s*at (\S+?)(?::(\d+))(?::(\d+))\s*$/i;

// This regex matches all the frames that have a function name.
const chromeRegex =
  /^\s*at (?:(.+?\)(?: \[.+\])?|.*?) ?\((?:address at )?)?(?:async )?((?:<anonymous>|[-a-z]+:|.*bundle|\/)?.*?)(?::(\d+))?(?::(\d+))?\)?\s*$/i;

const chromeEvalRegex = /\((\S*)(?::(\d+))(?::(\d+))\)/;

// Chromium based browsers: Chrome, Brave, new Opera, new Edge
// We cannot call this variable `chrome` because it can conflict with global `chrome` variable in certain environments
// See: https://github.com/getsentry/sentry-javascript/issues/6880
const chromeStackParserFn = line => {
  // If the stack line has no function name, we need to parse it differently
  const noFnParts = chromeRegexNoFnName.exec(line) ;

  if (noFnParts) {
    const [, filename, line, col] = noFnParts;
    return createFrame(filename, UNKNOWN_FUNCTION, +line, +col);
  }

  const parts = chromeRegex.exec(line) ;

  if (parts) {
    const isEval = parts[2] && parts[2].indexOf('eval') === 0; // start of line

    if (isEval) {
      const subMatch = chromeEvalRegex.exec(parts[2]) ;

      if (subMatch) {
        // throw out eval line/column and use top-most line/column number
        parts[2] = subMatch[1]; // url
        parts[3] = subMatch[2]; // line
        parts[4] = subMatch[3]; // column
      }
    }

    // Kamil: One more hack won't hurt us right? Understanding and adding more rules on top of these regexps right now
    // would be way too time consuming. (TODO: Rewrite whole RegExp to be more readable)
    const [func, filename] = extractSafariExtensionDetails(parts[1] || UNKNOWN_FUNCTION, parts[2]);

    return createFrame(filename, func, parts[3] ? +parts[3] : undefined, parts[4] ? +parts[4] : undefined);
  }

  return;
};

const chromeStackLineParser = [CHROME_PRIORITY, chromeStackParserFn];

// gecko regex: `(?:bundle|\d+\.js)`: `bundle` is for react native, `\d+\.js` also but specifically for ram bundles because it
// generates filenames without a prefix like `file://` the filenames in the stacktrace are just 42.js
// We need this specific case for now because we want no other regex to match.
const geckoREgex =
  /^\s*(.*?)(?:\((.*?)\))?(?:^|@)?((?:[-a-z]+)?:\/.*?|\[native code\]|[^@]*(?:bundle|\d+\.js)|\/[\w\-. /=]+)(?::(\d+))?(?::(\d+))?\s*$/i;
const geckoEvalRegex = /(\S+) line (\d+)(?: > eval line \d+)* > eval/i;

const gecko = line => {
  const parts = geckoREgex.exec(line) ;

  if (parts) {
    const isEval = parts[3] && parts[3].indexOf(' > eval') > -1;
    if (isEval) {
      const subMatch = geckoEvalRegex.exec(parts[3]) ;

      if (subMatch) {
        // throw out eval line/column and use top-most line number
        parts[1] = parts[1] || 'eval';
        parts[3] = subMatch[1];
        parts[4] = subMatch[2];
        parts[5] = ''; // no column when eval
      }
    }

    let filename = parts[3];
    let func = parts[1] || UNKNOWN_FUNCTION;
    [func, filename] = extractSafariExtensionDetails(func, filename);

    return createFrame(filename, func, parts[4] ? +parts[4] : undefined, parts[5] ? +parts[5] : undefined);
  }

  return;
};

const geckoStackLineParser = [GECKO_PRIORITY, gecko];

const winjsRegex = /^\s*at (?:((?:\[object object\])?.+) )?\(?((?:[-a-z]+):.*?):(\d+)(?::(\d+))?\)?\s*$/i;

const winjs = line => {
  const parts = winjsRegex.exec(line) ;

  return parts
    ? createFrame(parts[2], parts[1] || UNKNOWN_FUNCTION, +parts[3], parts[4] ? +parts[4] : undefined)
    : undefined;
};

const winjsStackLineParser = [WINJS_PRIORITY, winjs];

const opera10Regex = / line (\d+).*script (?:in )?(\S+)(?:: in function (\S+))?$/i;

const opera10 = line => {
  const parts = opera10Regex.exec(line) ;
  return parts ? createFrame(parts[2], parts[3] || UNKNOWN_FUNCTION, +parts[1]) : undefined;
};

const opera10StackLineParser = [OPERA10_PRIORITY, opera10];

const opera11Regex =
  / line (\d+), column (\d+)\s*(?:in (?:<anonymous function: ([^>]+)>|([^)]+))\(.*\))? in (.*):\s*$/i;

const opera11 = line => {
  const parts = opera11Regex.exec(line) ;
  return parts ? createFrame(parts[5], parts[3] || parts[4] || UNKNOWN_FUNCTION, +parts[1], +parts[2]) : undefined;
};

const opera11StackLineParser = [OPERA11_PRIORITY, opera11];

const defaultStackLineParsers = [chromeStackLineParser, geckoStackLineParser];

const defaultStackParser = createStackParser(...defaultStackLineParsers);

/**
 * Safari web extensions, starting version unknown, can produce "frames-only" stacktraces.
 * What it means, is that instead of format like:
 *
 * Error: wat
 *   at function@url:row:col
 *   at function@url:row:col
 *   at function@url:row:col
 *
 * it produces something like:
 *
 *   function@url:row:col
 *   function@url:row:col
 *   function@url:row:col
 *
 * Because of that, it won't be captured by `chrome` RegExp and will fall into `Gecko` branch.
 * This function is extracted so that we can use it in both places without duplicating the logic.
 * Unfortunately "just" changing RegExp is too complicated now and making it pass all tests
 * and fix this case seems like an impossible, or at least way too time-consuming task.
 */
const extractSafariExtensionDetails = (func, filename) => {
  const isSafariExtension = func.indexOf('safari-extension') !== -1;
  const isSafariWebExtension = func.indexOf('safari-web-extension') !== -1;

  return isSafariExtension || isSafariWebExtension
    ? [
        func.indexOf('@') !== -1 ? (func.split('@')[0] ) : UNKNOWN_FUNCTION,
        isSafariExtension ? `safari-extension:${filename}` : `safari-web-extension:${filename}`,
      ]
    : [func, filename];
};


//# sourceMappingURL=stack-parsers.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry-internal/browser-utils/build/esm/debug-build.js
/**
 * This serves as a build time flag that will be true by default, but false in non-debug builds or if users replace `__SENTRY_DEBUG__` in their generated code.
 *
 * ATTENTION: This constant must never cross package boundaries (i.e. be exported) to guarantee that it can be used for tree shaking.
 */
const build_esm_debug_build_DEBUG_BUILD = (typeof __SENTRY_DEBUG__ === 'undefined' || __SENTRY_DEBUG__);


//# sourceMappingURL=debug-build.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry-internal/browser-utils/build/esm/getNativeImplementation.js




/**
 * We generally want to use window.fetch / window.setTimeout.
 * However, in some cases this may be wrapped (e.g. by Zone.js for Angular),
 * so we try to get an unpatched version of this from a sandboxed iframe.
 */

const cachedImplementations = {};

/**
 * Get the native implementation of a browser function.
 *
 * This can be used to ensure we get an unwrapped version of a function, in cases where a wrapped function can lead to problems.
 *
 * The following methods can be retrieved:
 * - `setTimeout`: This can be wrapped by e.g. Angular, causing change detection to be triggered.
 * - `fetch`: This can be wrapped by e.g. ad-blockers, causing an infinite loop when a request is blocked.
 */
function getNativeImplementation(
  name,
) {
  const cached = cachedImplementations[name];
  if (cached) {
    return cached;
  }

  let impl = types_WINDOW[name] ;

  // Fast path to avoid DOM I/O
  if (isNativeFunction(impl)) {
    return (cachedImplementations[name] = impl.bind(types_WINDOW) );
  }

  const document = types_WINDOW.document;
  // eslint-disable-next-line deprecation/deprecation
  if (document && typeof document.createElement === 'function') {
    try {
      const sandbox = document.createElement('iframe');
      sandbox.hidden = true;
      document.head.appendChild(sandbox);
      const contentWindow = sandbox.contentWindow;
      if (contentWindow && contentWindow[name]) {
        impl = contentWindow[name] ;
      }
      document.head.removeChild(sandbox);
    } catch (e) {
      // Could not create sandbox iframe, just use window.xxx
      build_esm_debug_build_DEBUG_BUILD && logger_logger.warn(`Could not create sandbox iframe for ${name} check, bailing to window.${name}: `, e);
    }
  }

  // Sanity check: This _should_ not happen, but if it does, we just skip caching...
  // This can happen e.g. in tests where fetch may not be available in the env, or similar.
  if (!impl) {
    return impl;
  }

  return (cachedImplementations[name] = impl.bind(types_WINDOW) );
}

/** Clear a cached implementation. */
function clearCachedImplementation(name) {
  cachedImplementations[name] = undefined;
}

/**
 * A special usecase for incorrectly wrapped Fetch APIs in conjunction with ad-blockers.
 * Whenever someone wraps the Fetch API and returns the wrong promise chain,
 * this chain becomes orphaned and there is no possible way to capture it's rejections
 * other than allowing it bubble up to this very handler. eg.
 *
 * const f = window.fetch;
 * window.fetch = function () {
 *   const p = f.apply(this, arguments);
 *
 *   p.then(function() {
 *     console.log('hi.');
 *   });
 *
 *   return p;
 * }
 *
 * `p.then(function () { ... })` is producing a completely separate promise chain,
 * however, what's returned is `p` - the result of original `fetch` call.
 *
 * This mean, that whenever we use the Fetch API to send our own requests, _and_
 * some ad-blocker blocks it, this orphaned chain will _always_ reject,
 * effectively causing another event to be captured.
 * This makes a whole process become an infinite loop, which we need to somehow
 * deal with, and break it in one way or another.
 *
 * To deal with this issue, we are making sure that we _always_ use the real
 * browser Fetch API, instead of relying on what `window.fetch` exposes.
 * The only downside to this would be missing our own requests as breadcrumbs,
 * but because we are already not doing this, it should be just fine.
 *
 * Possible failed fetch error messages per-browser:
 *
 * Chrome:  Failed to fetch
 * Edge:    Failed to Fetch
 * Firefox: NetworkError when attempting to fetch resource
 * Safari:  resource blocked by content blocker
 */
function getNativeImplementation_fetch(...rest) {
  return getNativeImplementation('fetch')(...rest);
}

/**
 * Get an unwrapped `setTimeout` method.
 * This ensures that even if e.g. Angular wraps `setTimeout`, we get the native implementation,
 * avoiding triggering change detection.
 */
function getNativeImplementation_setTimeout(...rest) {
  return getNativeImplementation('setTimeout')(...rest);
}


//# sourceMappingURL=getNativeImplementation.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/promisebuffer.js



/**
 * Creates an new PromiseBuffer object with the specified limit
 * @param limit max number of promises that can be stored in the buffer
 */
function makePromiseBuffer(limit) {
  const buffer = [];

  function isReady() {
    return limit === undefined || buffer.length < limit;
  }

  /**
   * Remove a promise from the queue.
   *
   * @param task Can be any PromiseLike<T>
   * @returns Removed promise.
   */
  function remove(task) {
    return buffer.splice(buffer.indexOf(task), 1)[0] || Promise.resolve(undefined);
  }

  /**
   * Add a promise (representing an in-flight action) to the queue, and set it to remove itself on fulfillment.
   *
   * @param taskProducer A function producing any PromiseLike<T>; In previous versions this used to be `task:
   *        PromiseLike<T>`, but under that model, Promises were instantly created on the call-site and their executor
   *        functions therefore ran immediately. Thus, even if the buffer was full, the action still happened. By
   *        requiring the promise to be wrapped in a function, we can defer promise creation until after the buffer
   *        limit check.
   * @returns The original promise.
   */
  function add(taskProducer) {
    if (!isReady()) {
      return rejectedSyncPromise(new SentryError('Not adding Promise because buffer limit was reached.'));
    }

    // start the task and add its promise to the queue
    const task = taskProducer();
    if (buffer.indexOf(task) === -1) {
      buffer.push(task);
    }
    void task
      .then(() => remove(task))
      // Use `then(null, rejectionHandler)` rather than `catch(rejectionHandler)` so that we can use `PromiseLike`
      // rather than `Promise`. `PromiseLike` doesn't have a `.catch` method, making its polyfill smaller. (ES5 didn't
      // have promises, so TS has to polyfill when down-compiling.)
      .then(null, () =>
        remove(task).then(null, () => {
          // We have to add another catch here because `remove()` starts a new promise chain.
        }),
      );
    return task;
  }

  /**
   * Wait for all promises in the queue to resolve or for timeout to expire, whichever comes first.
   *
   * @param timeout The time, in ms, after which to resolve to `false` if the queue is still non-empty. Passing `0` (or
   * not passing anything) will make the promise wait as long as it takes for the queue to drain before resolving to
   * `true`.
   * @returns A promise which will resolve to `true` if the queue is already empty or drains before the timeout, and
   * `false` otherwise
   */
  function drain(timeout) {
    return new SyncPromise((resolve, reject) => {
      let counter = buffer.length;

      if (!counter) {
        return resolve(true);
      }

      // wait for `timeout` ms and then resolve to `false` (if not cancelled first)
      const capturedSetTimeout = setTimeout(() => {
        if (timeout && timeout > 0) {
          resolve(false);
        }
      }, timeout);

      // if all promises resolve in time, cancel the timer and resolve to `true`
      buffer.forEach(item => {
        void resolvedSyncPromise(item).then(() => {
          if (!--counter) {
            clearTimeout(capturedSetTimeout);
            resolve(true);
          }
        }, reject);
      });
    });
  }

  return {
    $: buffer,
    add,
    drain,
  };
}


//# sourceMappingURL=promisebuffer.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/utils-hoist/ratelimit.js
// Intentionally keeping the key broad, as we don't know for sure what rate limit headers get returned from backend

const DEFAULT_RETRY_AFTER = 60 * 1000; // 60 seconds

/**
 * Extracts Retry-After value from the request header or returns default value
 * @param header string representation of 'Retry-After' header
 * @param now current unix timestamp
 *
 */
function parseRetryAfterHeader(header, now = Date.now()) {
  const headerDelay = parseInt(`${header}`, 10);
  if (!isNaN(headerDelay)) {
    return headerDelay * 1000;
  }

  const headerDate = Date.parse(`${header}`);
  if (!isNaN(headerDate)) {
    return headerDate - now;
  }

  return DEFAULT_RETRY_AFTER;
}

/**
 * Gets the time that the given category is disabled until for rate limiting.
 * In case no category-specific limit is set but a general rate limit across all categories is active,
 * that time is returned.
 *
 * @return the time in ms that the category is disabled until or 0 if there's no active rate limit.
 */
function disabledUntil(limits, dataCategory) {
  return limits[dataCategory] || limits.all || 0;
}

/**
 * Checks if a category is rate limited
 */
function isRateLimited(limits, dataCategory, now = Date.now()) {
  return disabledUntil(limits, dataCategory) > now;
}

/**
 * Update ratelimits from incoming headers.
 *
 * @return the updated RateLimits object.
 */
function updateRateLimits(
  limits,
  { statusCode, headers },
  now = Date.now(),
) {
  const updatedRateLimits = {
    ...limits,
  };

  // "The name is case-insensitive."
  // https://developer.mozilla.org/en-US/docs/Web/API/Headers/get
  const rateLimitHeader = headers && headers['x-sentry-rate-limits'];
  const retryAfterHeader = headers && headers['retry-after'];

  if (rateLimitHeader) {
    /**
     * rate limit headers are of the form
     *     <header>,<header>,..
     * where each <header> is of the form
     *     <retry_after>: <categories>: <scope>: <reason_code>: <namespaces>
     * where
     *     <retry_after> is a delay in seconds
     *     <categories> is the event type(s) (error, transaction, etc) being rate limited and is of the form
     *         <category>;<category>;...
     *     <scope> is what's being limited (org, project, or key) - ignored by SDK
     *     <reason_code> is an arbitrary string like "org_quota" - ignored by SDK
     *     <namespaces> Semicolon-separated list of metric namespace identifiers. Defines which namespace(s) will be affected.
     *         Only present if rate limit applies to the metric_bucket data category.
     */
    for (const limit of rateLimitHeader.trim().split(',')) {
      const [retryAfter, categories, , , namespaces] = limit.split(':', 5) ;
      const headerDelay = parseInt(retryAfter, 10);
      const delay = (!isNaN(headerDelay) ? headerDelay : 60) * 1000; // 60sec default
      if (!categories) {
        updatedRateLimits.all = now + delay;
      } else {
        for (const category of categories.split(';')) {
          if (category === 'metric_bucket') {
            // namespaces will be present when category === 'metric_bucket'
            if (!namespaces || namespaces.split(';').includes('custom')) {
              updatedRateLimits[category] = now + delay;
            }
          } else {
            updatedRateLimits[category] = now + delay;
          }
        }
      }
    }
  } else if (retryAfterHeader) {
    updatedRateLimits.all = now + parseRetryAfterHeader(retryAfterHeader, now);
  } else if (statusCode === 429) {
    updatedRateLimits.all = now + 60 * 1000;
  }

  return updatedRateLimits;
}


//# sourceMappingURL=ratelimit.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/core/build/esm/transports/base.js








const DEFAULT_TRANSPORT_BUFFER_SIZE = 64;

/**
 * Creates an instance of a Sentry `Transport`
 *
 * @param options
 * @param makeRequest
 */
function createTransport(
  options,
  makeRequest,
  buffer = makePromiseBuffer(
    options.bufferSize || DEFAULT_TRANSPORT_BUFFER_SIZE,
  ),
) {
  let rateLimits = {};
  const flush = (timeout) => buffer.drain(timeout);

  function send(envelope) {
    const filteredEnvelopeItems = [];

    // Drop rate limited items from envelope
    forEachEnvelopeItem(envelope, (item, type) => {
      const dataCategory = envelopeItemTypeToDataCategory(type);
      if (isRateLimited(rateLimits, dataCategory)) {
        const event = getEventForEnvelopeItem(item, type);
        options.recordDroppedEvent('ratelimit_backoff', dataCategory, event);
      } else {
        filteredEnvelopeItems.push(item);
      }
    });

    // Skip sending if envelope is empty after filtering out rate limited events
    if (filteredEnvelopeItems.length === 0) {
      return resolvedSyncPromise({});
    }

    const filteredEnvelope = envelope_createEnvelope(envelope[0], filteredEnvelopeItems );

    // Creates client report for each item in an envelope
    const recordEnvelopeLoss = (reason) => {
      forEachEnvelopeItem(filteredEnvelope, (item, type) => {
        const event = getEventForEnvelopeItem(item, type);
        options.recordDroppedEvent(reason, envelopeItemTypeToDataCategory(type), event);
      });
    };

    const requestTask = () =>
      makeRequest({ body: serializeEnvelope(filteredEnvelope) }).then(
        response => {
          // We don't want to throw on NOK responses, but we want to at least log them
          if (response.statusCode !== undefined && (response.statusCode < 200 || response.statusCode >= 300)) {
            debug_build_DEBUG_BUILD && logger_logger.warn(`Sentry responded with status code ${response.statusCode} to sent event.`);
          }

          rateLimits = updateRateLimits(rateLimits, response);
          return response;
        },
        error => {
          recordEnvelopeLoss('network_error');
          throw error;
        },
      );

    return buffer.add(requestTask).then(
      result => result,
      error => {
        if (error instanceof SentryError) {
          debug_build_DEBUG_BUILD && logger_logger.error('Skipped sending event because buffer is full.');
          recordEnvelopeLoss('queue_overflow');
          return resolvedSyncPromise({});
        } else {
          throw error;
        }
      },
    );
  }

  return {
    send,
    flush,
  };
}

function getEventForEnvelopeItem(item, type) {
  if (type !== 'event' && type !== 'transaction') {
    return undefined;
  }

  return Array.isArray(item) ? (item )[1] : undefined;
}


//# sourceMappingURL=base.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/transports/fetch.js



/**
 * Creates a Transport that uses the Fetch API to send events to Sentry.
 */
function makeFetchTransport(
  options,
  nativeFetch = getNativeImplementation('fetch'),
) {
  let pendingBodySize = 0;
  let pendingCount = 0;

  function makeRequest(request) {
    const requestSize = request.body.length;
    pendingBodySize += requestSize;
    pendingCount++;

    const requestOptions = {
      body: request.body,
      method: 'POST',
      referrerPolicy: 'origin',
      headers: options.headers,
      // Outgoing requests are usually cancelled when navigating to a different page, causing a "TypeError: Failed to
      // fetch" error and sending a "network_error" client-outcome - in Chrome, the request status shows "(cancelled)".
      // The `keepalive` flag keeps outgoing requests alive, even when switching pages. We want this since we're
      // frequently sending events right before the user is switching pages (eg. when finishing navigation transactions).
      // Gotchas:
      // - `keepalive` isn't supported by Firefox
      // - As per spec (https://fetch.spec.whatwg.org/#http-network-or-cache-fetch):
      //   If the sum of contentLength and inflightKeepaliveBytes is greater than 64 kibibytes, then return a network error.
      //   We will therefore only activate the flag when we're below that limit.
      // There is also a limit of requests that can be open at the same time, so we also limit this to 15
      // See https://github.com/getsentry/sentry-javascript/pull/7553 for details
      keepalive: pendingBodySize <= 60000 && pendingCount < 15,
      ...options.fetchOptions,
    };

    if (!nativeFetch) {
      clearCachedImplementation('fetch');
      return rejectedSyncPromise('No fetch implementation available');
    }

    try {
      // TODO: This may need a `suppressTracing` call in the future when we switch the browser SDK to OTEL
      return nativeFetch(options.url, requestOptions).then(response => {
        pendingBodySize -= requestSize;
        pendingCount--;
        return {
          statusCode: response.status,
          headers: {
            'x-sentry-rate-limits': response.headers.get('X-Sentry-Rate-Limits'),
            'retry-after': response.headers.get('Retry-After'),
          },
        };
      });
    } catch (e) {
      clearCachedImplementation('fetch');
      pendingBodySize -= requestSize;
      pendingCount--;
      return rejectedSyncPromise(e);
    }
  }

  return createTransport(options, makeRequest);
}


//# sourceMappingURL=fetch.js.map

;// CONCATENATED MODULE: ./node_modules/@sentry/browser/build/npm/esm/sdk.js













/** Get the default integrations for the browser SDK. */
function getDefaultIntegrations(options) {
  /**
   * Note: Please make sure this stays in sync with Angular SDK, which re-exports
   * `getDefaultIntegrations` but with an adjusted set of integrations.
   */
  const integrations = [
    inboundFiltersIntegration(),
    functionToStringIntegration(),
    browserApiErrorsIntegration(),
    breadcrumbsIntegration(),
    globalHandlersIntegration(),
    linkedErrorsIntegration(),
    dedupeIntegration(),
    httpContextIntegration(),
  ];

  // eslint-disable-next-line deprecation/deprecation
  if (options.autoSessionTracking !== false) {
    integrations.push(browserSessionIntegration());
  }

  return integrations;
}

function applyDefaultOptions(optionsArg = {}) {
  const defaultOptions = {
    defaultIntegrations: getDefaultIntegrations(optionsArg),
    release:
      typeof __SENTRY_RELEASE__ === 'string' // This allows build tooling to find-and-replace __SENTRY_RELEASE__ to inject a release value
        ? __SENTRY_RELEASE__
        : helpers_WINDOW.SENTRY_RELEASE && helpers_WINDOW.SENTRY_RELEASE.id // This supports the variable that sentry-webpack-plugin injects
          ? helpers_WINDOW.SENTRY_RELEASE.id
          : undefined,
    autoSessionTracking: true,
    sendClientReports: true,
  };

  // TODO: Instead of dropping just `defaultIntegrations`, we should simply
  // call `dropUndefinedKeys` on the entire `optionsArg`.
  // However, for this to work we need to adjust the `hasTracingEnabled()` logic
  // first as it differentiates between `undefined` and the key not being in the object.
  if (optionsArg.defaultIntegrations == null) {
    delete optionsArg.defaultIntegrations;
  }

  return { ...defaultOptions, ...optionsArg };
}

function shouldShowBrowserExtensionError() {
  const windowWithMaybeExtension =
    typeof helpers_WINDOW.window !== 'undefined' && (helpers_WINDOW );
  if (!windowWithMaybeExtension) {
    // No need to show the error if we're not in a browser window environment (e.g. service workers)
    return false;
  }

  const extensionKey = windowWithMaybeExtension.chrome ? 'chrome' : 'browser';
  const extensionObject = windowWithMaybeExtension[extensionKey];

  const runtimeId = extensionObject && extensionObject.runtime && extensionObject.runtime.id;
  const href = (helpers_WINDOW.location && helpers_WINDOW.location.href) || '';

  const extensionProtocols = ['chrome-extension:', 'moz-extension:', 'ms-browser-extension:', 'safari-web-extension:'];

  // Running the SDK in a dedicated extension page and calling Sentry.init is fine; no risk of data leakage
  const isDedicatedExtensionPage =
    !!runtimeId && helpers_WINDOW === helpers_WINDOW.top && extensionProtocols.some(protocol => href.startsWith(`${protocol}//`));

  // Running the SDK in NW.js, which appears like a browser extension but isn't, is also fine
  // see: https://github.com/getsentry/sentry-javascript/issues/12668
  const isNWjs = typeof windowWithMaybeExtension.nw !== 'undefined';

  return !!runtimeId && !isDedicatedExtensionPage && !isNWjs;
}

/**
 * A magic string that build tooling can leverage in order to inject a release value into the SDK.
 */

/**
 * The Sentry Browser SDK Client.
 *
 * To use this SDK, call the {@link init} function as early as possible when
 * loading the web page. To set context information or send manual events, use
 * the provided methods.
 *
 * @example
 *
 * ```
 *
 * import { init } from '@sentry/browser';
 *
 * init({
 *   dsn: '__DSN__',
 *   // ...
 * });
 * ```
 *
 * @example
 * ```
 *
 * import { addBreadcrumb } from '@sentry/browser';
 * addBreadcrumb({
 *   message: 'My Breadcrumb',
 *   // ...
 * });
 * ```
 *
 * @example
 *
 * ```
 *
 * import * as Sentry from '@sentry/browser';
 * Sentry.captureMessage('Hello, world!');
 * Sentry.captureException(new Error('Good bye'));
 * Sentry.captureEvent({
 *   message: 'Manual',
 *   stacktrace: [
 *     // ...
 *   ],
 * });
 * ```
 *
 * @see {@link BrowserOptions} for documentation on configuration options.
 */
function sdk_init(browserOptions = {}) {
  const options = applyDefaultOptions(browserOptions);

  if (!options.skipBrowserExtensionCheck && shouldShowBrowserExtensionError()) {
    consoleSandbox(() => {
      // eslint-disable-next-line no-console
      console.error(
        '[Sentry] You cannot run Sentry this way in a browser extension, check: https://docs.sentry.io/platforms/javascript/best-practices/browser-extensions/',
      );
    });
    return;
  }

  if (esm_debug_build_DEBUG_BUILD) {
    if (!supportsFetch()) {
      logger_logger.warn(
        'No Fetch API detected. The Sentry SDK requires a Fetch API compatible environment to send events. Please add a Fetch API polyfill.',
      );
    }
  }
  const clientOptions = {
    ...options,
    stackParser: stackParserFromStackParserOptions(options.stackParser || defaultStackParser),
    integrations: getIntegrationsToSetup(options),
    transport: options.transport || makeFetchTransport,
  };

  return initAndBind(BrowserClient, clientOptions);
}

/**
 * All properties the report dialog supports
 */

/**
 * Present the user with a report dialog.
 *
 * @param options Everything is optional, we try to fetch all info need from the global scope.
 */
function showReportDialog(options = {}) {
  // doesn't work without a document (React Native)
  if (!WINDOW.document) {
    DEBUG_BUILD && logger.error('Global document not defined in showReportDialog call');
    return;
  }

  const scope = getCurrentScope();
  const client = scope.getClient();
  const dsn = client && client.getDsn();

  if (!dsn) {
    DEBUG_BUILD && logger.error('DSN not configured for showReportDialog call');
    return;
  }

  if (scope) {
    options.user = {
      ...scope.getUser(),
      ...options.user,
    };
  }

  if (!options.eventId) {
    const eventId = lastEventId();
    if (eventId) {
      options.eventId = eventId;
    }
  }

  const script = WINDOW.document.createElement('script');
  script.async = true;
  script.crossOrigin = 'anonymous';
  script.src = getReportDialogEndpoint(dsn, options);

  if (options.onLoad) {
    script.onload = options.onLoad;
  }

  const { onClose } = options;
  if (onClose) {
    const reportDialogClosedMessageHandler = (event) => {
      if (event.data === '__sentry_reportdialog_closed__') {
        try {
          onClose();
        } finally {
          WINDOW.removeEventListener('message', reportDialogClosedMessageHandler);
        }
      }
    };
    WINDOW.addEventListener('message', reportDialogClosedMessageHandler);
  }

  const injectionPoint = WINDOW.document.head || WINDOW.document.body;
  if (injectionPoint) {
    injectionPoint.appendChild(script);
  } else {
    DEBUG_BUILD && logger.error('Not injecting report dialog. No injection point found in HTML');
  }
}

/**
 * This function is here to be API compatible with the loader.
 * @hidden
 */
function forceLoad() {
  // Noop
}

/**
 * This function is here to be API compatible with the loader.
 * @hidden
 */
function onLoad(callback) {
  callback();
}

/**
 * Captures user feedback and sends it to Sentry.
 *
 * @deprecated Use `captureFeedback` instead.
 */
function captureUserFeedback(feedback) {
  const client = getClient();
  if (client) {
    // eslint-disable-next-line deprecation/deprecation
    client.captureUserFeedback(feedback);
  }
}


//# sourceMappingURL=sdk.js.map

;// CONCATENATED MODULE: ./src/sdk/main.js




var main_excluded = ["logLevel", "logOutput"];
var main_Promise = typeof Promise === 'undefined' ? (__webpack_require__(2702).Promise) : Promise;
/*:: // 
import { type InitOptionsT, type LogOptionsT, type EventParamsT, type GlobalParamsT, type CustomErrorT, type ActivityStateMapT, type SmartBannerOptionsT, type AttributionMapT } from './types';*/



























// SentryWT.init({
//   dsn: 'https://fbb048eabd1c4eb99c47749c716b739f@glitchtip.wisetrackdev.ir/20',
//   tracesSampleRate: 1.0, 
//   // release: '0.9.0-alpha'
// })

// Initialize Sentry with a specific configuration
sdk_init({
  dsn: 'https://fbb048eabd1c4eb99c47749c716b739f@glitchtip.wisetrackdev.ir/20',
  release: '0.9.0-alpha',
  environment: 'production' // or other contexts
});

// This will ensure the scope is confined to this instance of the SDK
currentScopes_withScope(function (scope) {
  // scope is the current scope inside of this callback!
  scope.setTag('my-tag', 'my value');
  // this tag will only be applied to events captured inside of this callback
  // the following event will have the tag:
  captureException(new Error('my error'));
});
/*:: type InitConfigT = $ReadOnly<{|...InitOptionsT, ...LogOptionsT|}>*/
/**
 * In-memory parameters to be used if restarting
 *
 * @type {Object}
 * @private
 */
var main_options /*: ?InitOptionsT*/ = null;

/**
 * Flag to mark id sdk is in starting process
 *
 * @type {boolean}
 * @private
 */
var _isInitialising /*: boolean*/ = false;

/**
 * Flag to mark if sdk is started
 *
 * @type {boolean}
 * @private
 */
var _isStarted /*: boolean*/ = false;

/**
 * Flag to mark if sdk is installed to delay public methods until SDK is ready to perform them
 *
 * @type {boolean}
 * @private
 */
var _isInstalled /*: boolean*/ = false;

/**
 * SmartBanner instance
 *
 * @private
 */
var _smartBanner /*: ?SmartBanner*/ = null;

/**
 * Initiate the instance with parameters
 *
 * @param {Object} options
 * @param {string} logLevel
 * @param {string} logOutput
 */
function initSdk() {
  return _initSdk.apply(this, arguments);
}
/**
 * Get user's current attribution information
 *
 * @returns {AttributionMapT|undefined} current attribution information if available or `undefined` otherwise
 */
function _initSdk() {
  _initSdk = asyncToGenerator_asyncToGenerator( /*#__PURE__*/regeneratorRuntime_regeneratorRuntime().mark(function _callee() {
    var _ref2,
      logLevel,
      logOutput,
      options,
      CONFIG_API_RETRY,
      versionConfig,
      _args = arguments;
    return regeneratorRuntime_regeneratorRuntime().wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _ref2 = _args.length > 0 && _args[0] !== undefined ? _args[0] : {}, logLevel = _ref2.logLevel, logOutput = _ref2.logOutput, options = _objectWithoutProperties(_ref2, main_excluded);
            sdk_logger.setLogLevel(logLevel, logOutput);
            _context.prev = 2;
            CONFIG_API_RETRY = 0;
            versionConfig = getConfig(PlatformType.WEB, EnvirmentType.PRODUCTION);
          case 5:
            if (!(CONFIG_API_RETRY <= 3)) {
              _context.next = 16;
              break;
            }
            _context.next = 8;
            return sendConfig(versionConfig);
          case 8:
            console.log('HTTP_STATUS_CODE: ', constants_configs.HTTP_STATUS_CODE);
            if (!(constants_configs.HTTP_STATUS_CODE == 200)) {
              _context.next = 11;
              break;
            }
            return _context.abrupt("break", 16);
          case 11:
            _context.next = 13;
            return sleep(10000);
          case 13:
            CONFIG_API_RETRY++;
            _context.next = 5;
            break;
          case 16:
            console.log('app_settings_enabled: ', constants_configs.app_settings_enabled);
            if (!constants_configs.app_settings_enabled) {
              _context.next = 20;
              break;
            }
            _context.next = 20;
            return callSettingsApi(options.appToken);
          case 20:
            if (!constants_configs.sdk_enabled) {
              _context.next = 28;
              break;
            }
            if (!_isInitialised()) {
              _context.next = 24;
              break;
            }
            sdk_logger.error('You already initiated your instance');
            return _context.abrupt("return");
          case 24:
            if (!config.hasMissing(options)) {
              _context.next = 26;
              break;
            }
            return _context.abrupt("return");
          case 26:
            _isInitialising = true;
            storage.init(options.namespace).then(function (availableStorage) {
              if (availableStorage.type === STORAGE_TYPES.NO_STORAGE) {
                sdk_logger.error('WiseTrack SDK can not start, there is no storage available');
                return;
              }
              sdk_logger.info("Available storage is ".concat(availableStorage.type));
              main_options = _objectSpread2({}, options);
              _start(options);
            });
          case 28:
            _context.next = 33;
            break;
          case 30:
            _context.prev = 30;
            _context.t0 = _context["catch"](2);
            sdk_logger.error('Error initializing SDK:', _context.t0);
          case 33:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, null, [[2, 30]]);
  }));
  return _initSdk.apply(this, arguments);
}
function main_getAttribution() /*: ?AttributionMapT*/{
  return _preCheck('get attribution', function () {
    return activity_state.getAttribution();
  });
}

/**
 * Get `web_uuid` - a unique ID of user generated per subdomain and per browser
 *
 * @returns {string|undefined} `web_uuid` if available or `undefined` otherwise
 */
function main_getWebUUID() /*: ?string*/{
  return _preCheck('get web_uuid', function () {
    return activity_state.getWebUUID();
  });
}
function setReferrer(referrer /*: string*/) {
  if (!referrer || typeof referrer !== 'string') {
    sdk_logger.error('You must provide a string referrer');
    return;
  }
  _preCheck('setting reftag', function (timestamp) {
    return sdkClick(referrer, timestamp);
  }, {
    schedule: true,
    waitForInitFinished: true,
    optionalInit: true
  });
}

/**
 * Track event with already initiated instance
 *
 * @param {Object} params
 */
function trackEvent(params /*: EventParamsT*/) /*: Promise<void>*/{
  return _internalTrackEvent(params);
}

/**
 * Add global callback parameters
 *
 * @param {Array} params
 */
function addGlobalCallbackParameters(params /*: Array<GlobalParamsT>*/) /*: void*/{
  _preCheck('add global callback parameters', function () {
    return add(params, 'callback');
  });
}

/**
 * Add global partner parameters
 *
 * @param {Array} params
 */
function addGlobalPartnerParameters(params /*: Array<GlobalParamsT>*/) /*: void*/{
  _preCheck('add global partner parameters', function () {
    return add(params, 'partner');
  });
}

/**
 * Remove global callback parameter by key
 *
 * @param {string} key
 */
function removeGlobalCallbackParameter(key /*: string*/) /*: void*/{
  _preCheck('remove global callback parameter', function () {
    return remove(key, 'callback');
  });
}

/**
 * Remove global partner parameter by key
 *
 * @param {string} key
 */
function removeGlobalPartnerParameter(key /*: string*/) /*: void*/{
  _preCheck('remove global partner parameter', function () {
    return remove(key, 'partner');
  });
}

/**
 * Remove all global callback parameters
 */
function clearGlobalCallbackParameters() /*: void*/{
  _preCheck('remove all global callback parameters', function () {
    return removeAll('callback');
  });
}

/**
 * Remove all global partner parameters
 */
function clearGlobalPartnerParameters() /*: void*/{
  _preCheck('remove all global partner parameters', function () {
    return removeAll('partner');
  });
}

/**
 * Switch offline mode
 */
function switchToOfflineMode() /*: void*/{
  _preCheck('set offline mode', function () {
    return setOffline(true);
  });
}

/**
 * Switch online mode
 */
function switchBackToOnlineMode() /*: void*/{
  _preCheck('set online mode', function () {
    return setOffline(false);
  });
}

/**
 * Stop SDK
 */
function stop() /*: void*/{
  var done = disable();
  if (done && config.isInitialised()) {
    _shutdown();
  }
}

/**
 * Restart sdk if not GDPR forgotten
 */
function restart() /*: void*/{
  var done = restore();
  if (done && main_options) {
    _start(main_options);
  }
}

/**
 * Disable sdk and send GDPR-Forget-Me request
 */
function gdprForgetMe() /*: void*/{
  var done = forget();
  if (!done) {
    return;
  }
  done = gdpr_forget_device_disable();
  if (done && config.isInitialised()) {
    _pause();
  }
}

/**
 * Disable third party sharing
 */
function disableThirdPartySharing() /*: void*/{
  _preCheck('disable third-party sharing', _handleDisableThirdPartySharing, {
    schedule: true
  });
}
function initSmartBanner(options /*: SmartBannerOptionsT*/) /*: void*/{
  if (_smartBanner) {
    sdk_logger.error('Smart Banner already initialised');
    return;
  }
  _smartBanner = new SmartBanner(options);
}
function showSmartBanner() /*: void*/{
  if (!_smartBanner) {
    sdk_logger.error('Smart Banner is not initialised yet');
    return;
  }
  _smartBanner.show();
}
function hideSmartBanner() /*: void*/{
  if (!_smartBanner) {
    sdk_logger.error('Smart Banner is not initialised yet');
    return;
  }
  _smartBanner.hide();
}

/**
 * Handle third party sharing disable
 *
 * @private
 */
function _handleDisableThirdPartySharing() /*: void*/{
  var done = optOut();
  if (!done) {
    return;
  }
  sdk_third_party_sharing_disable();
}

/**
 * Handle GDPR-Forget-Me response
 *
 * @private
 */
function _handleGdprForgetMe() /*: void*/{
  if (disable_status() !== 'paused') {
    return;
  }
  gdpr_forget_device_finish();
  main_Promise.all([clear(), global_params_clear(), queue_clear()]).then(main_destroy);
}

/**
 * Check if sdk initialisation was started
 *
 * @private
 */
function _isInitialised() /*: boolean*/{
  return _isInitialising || config.isInitialised();
}

/**
 * Pause sdk by canceling:
 * - queue execution
 * - session watch
 * - attribution listener
 *
 * @private
 */
function _pause() /*: void*/{
  _isInitialising = false;
  _isStarted = false;
  scheduler_destroy();
  queue_destroy();
  session_destroy();
  attribution_destroy();
}

/**
 * Shutdown all dependencies
 * @private
 */
function _shutdown(async) /*: void*/{
  if (async) {
    sdk_logger.log('WiseTrack SDK has been shutdown due to asynchronous disable');
  }
  _pause();
  pub_sub_destroy();
  identity_destroy();
  listeners_destroy();
  storage.destroy();
  config.destroy();
}

/**
 * Destroy the instance
 *
 * @private
 */
function main_destroy() /*: void*/{
  _isInstalled = false;
  _shutdown();
  gdpr_forget_device_destroy();
  main_options = null;
  sdk_logger.log('WiseTrack SDK instance has been destroyed');
}

/**
 * Check the sdk status and proceed with certain actions
 *
 * @param {Object} activityState
 * @returns {Promise|boolean}
 * @private
 */
function main_continue(activityState /*: ActivityStateMapT*/) /*: Promise<void>*/{
  sdk_logger.log("WiseTrack SDK is starting with web_uuid set to ".concat(activityState.uuid));
  var isInstalled = activity_state.current.installed;
  gdpr_forget_device_check();
  if (!isInstalled) {
    third_party_sharing_check();
  }
  var sdkStatus = disable_status();
  var message = function message(rest) {
    return "WiseTrack SDK start has been interrupted ".concat(rest);
  };
  if (sdkStatus === 'off') {
    _shutdown();
    return main_Promise.reject({
      interrupted: true,
      message: message('due to complete async disable')
    });
  }
  if (sdkStatus === 'paused') {
    _pause();
    return main_Promise.reject({
      interrupted: true,
      message: message('due to partial async disable')
    });
  }
  if (_isStarted) {
    return main_Promise.reject({
      interrupted: true,
      message: message('due to multiple synchronous start attempt')
    });
  }
  run({
    cleanUp: true
  });
  return watch().then(function () {
    _isInitialising = false;
    _isStarted = true;
    if (isInstalled) {
      _handleSdkInstalled();
      third_party_sharing_check();
    }
  }).then(function () {
    if (!activityState.sdkClickSent) {
      WiseTrack.setReferrer('wisetrack-default-web-referrer');
    }
  }).then(function () {
    // if (!activityState.attrSent) {
    //   attributionCheck({ask_in: 3000})
    // }
  });
}

/**
 * Handles SDK installed and runs delayed tasks
 */
function _handleSdkInstalled() {
  _isInstalled = true;
  flush();
  unsubscribe('sdk:installed');
}

/**
 * Handle error coming from the chain of commands
 *
 * @param {Object|Error} error
 * @private
 */
function main_error(error /*: CustomErrorT | Error*/) {
  //SentryWT.captureEvent('0.9.0-alpha -> '+error)
  if (error.interrupted) {
    sdk_logger.log(error.message);
    return;
  }
  _shutdown();
  sdk_logger.error('WiseTrack SDK start has been canceled due to an error', error);
  if (error.stack) {
    throw error;
  }
}

/**
 * Start the execution by preparing the environment for the current usage
 * - prepares mandatory parameters
 * - register some global event listeners (online, offline events)
 * - subscribe to a GDPR-Forget-Me request event
 * - subscribe to the attribution change event
 * - register activity state if doesn't exist
 * - run pending GDPR-Forget-Me if pending
 * - run the package queue if not empty
 * - start watching the session
 *
 * @param {Object} options
 * @param {string} options.appToken
 * @param {string} options.environment
 * @param {string=} options.defaultTracker
 * @param {string=} options.externalDeviceId
 * @param {string=} options.customUrl
 * @param {number=} options.eventDeduplicationListLimit
 * @param {Function=} options.attributionCallback
 * @private
 */
function _start(_x) {
  return _start2.apply(this, arguments);
}
function _start2() {
  _start2 = asyncToGenerator_asyncToGenerator( /*#__PURE__*/regeneratorRuntime_regeneratorRuntime().mark(function _callee2(options /*: InitOptionsT*/) {
    return regeneratorRuntime_regeneratorRuntime().wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            if (!(disable_status() === 'off')) {
              _context2.next = 3;
              break;
            }
            sdk_logger.log('WiseTrack SDK is disabled, can not start the sdk');
            return _context2.abrupt("return");
          case 3:
            config.set(options);
            register();
            subscribe('sdk:installed', _handleSdkInstalled);
            subscribe('sdk:shutdown', function () {
              return _shutdown(true);
            });
            subscribe('sdk:gdpr-forget-me', _handleGdprForgetMe);
            subscribe('sdk:third-party-sharing-opt-out', third_party_sharing_finish);
            //subscribe('attribution:check', (e, result) => attributionCheck(result))

            if (typeof options.attributionCallback === 'function') {
              subscribe('attribution:change', options.attributionCallback);
            }
            if (!main_checkRefreshWebSite()) {
              sdkClick();
            }
            _context2.next = 13;
            return sleep(8000);
          case 13:
            start().then(main_continue).catch(main_error);
          case 14:
          case "end":
            return _context2.stop();
        }
      }
    }, _callee2);
  }));
  return _start2.apply(this, arguments);
}
function _internalTrackEvent(params /*: EventParamsT*/) {
  if (storage.getType() === STORAGE_TYPES.NO_STORAGE) {
    var reason = 'WiseTrack SDK can not track event, no storage available';
    sdk_logger.log(reason);
    return main_Promise.reject(reason);
  }
  if (disable_status() !== 'on') {
    var _reason = 'WiseTrack SDK is disabled, can not track event';
    sdk_logger.log(_reason);
    return main_Promise.reject(_reason);
  }
  if (!_isInitialised()) {
    var _reason2 = 'WiseTrack SDK can not track event, sdk instance is not initialized';
    sdk_logger.error(_reason2);
    return main_Promise.reject(_reason2);
  }
  return new main_Promise(function (resolve) {
    var _callback = function _callback(timestamp) {
      return resolve(event_event(params, timestamp));
    };
    if (!_isInstalled || !_isStarted && _isInitialised()) {
      _callback();
    } else {
      delay(_callback, 'track event');
      sdk_logger.log('Running track event is delayed until WiseTrack SDK is up');
    }
  });
}

/**
 * Check if it's possible to run provided method
 *
 * @param {string} description
 * @param {Function} callback
 * @param {boolean=false} schedule
 * @private
 */
function _preCheck(description /*: string*/, callback /*: () => mixed*/) /*: mixed*/{
  var _ref = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {},
    schedule = _ref.schedule,
    waitForInitFinished = _ref.waitForInitFinished,
    optionalInit = _ref.optionalInit;
  if (storage.getType() === STORAGE_TYPES.NO_STORAGE) {
    sdk_logger.log("WiseTrack SDK can not ".concat(description, ", no storage available"));
    return;
  }
  if (disable_status() !== 'on') {
    sdk_logger.log("WiseTrack SDK is disabled, can not ".concat(description));
    return;
  }
  if (!(optionalInit || _isInitialised()) && waitForInitFinished) {
    sdk_logger.error("WiseTrack SDK can not ".concat(description, ", sdk instance is not initialized"));
    return;
  }
  if (typeof callback === 'function') {
    if (schedule && !(_isInstalled && _isStarted) && (optionalInit || _isInitialised())) {
      delay(callback, description);
      sdk_logger.log("Running ".concat(description, " is delayed until WiseTrack SDK is up"));
    } else {
      return callback();
    }
  }
}
function _clearDatabase() {
  return storage.deleteDatabase();
}
function _restartAfterAsyncEnable() {
  sdk_logger.log('WiseTrack SDK has been restarted due to asynchronous enable');
  if (main_options) {
    _start(main_options);
  }
}

/**
 * Pauses the execution of code for a specified duration.
 * 
 * This function returns a Promise that resolves after the specified number of milliseconds (ms).
 * It can be used with `await` to introduce a delay in asynchronous code execution.
 *
 * @param {number} ms - The time to wait in milliseconds before the Promise resolves.
 * @returns 
 */
function sleep(ms) {
  return new main_Promise(function (resolve) {
    return setTimeout(resolve, ms);
  });
}
function main_checkRefreshWebSite() /*: Boolean*/{
  // You can also check if it's the first time the page was opened in the session
  if (sessionStorage.getItem('pageLoaded_sdk_click') === null) {
    sessionStorage.setItem('pageLoaded_sdk_click', 'true');
    return false;
  } else {
    return true;
  }
}
var WiseTrack = {
  initSdk: initSdk,
  getAttribution: main_getAttribution,
  getWebUUID: main_getWebUUID,
  setReferrer: setReferrer,
  trackEvent: trackEvent,
  addGlobalCallbackParameters: addGlobalCallbackParameters,
  addGlobalPartnerParameters: addGlobalPartnerParameters,
  removeGlobalCallbackParameter: removeGlobalCallbackParameter,
  removeGlobalPartnerParameter: removeGlobalPartnerParameter,
  clearGlobalCallbackParameters: clearGlobalCallbackParameters,
  clearGlobalPartnerParameters: clearGlobalPartnerParameters,
  switchToOfflineMode: switchToOfflineMode,
  switchBackToOnlineMode: switchBackToOnlineMode,
  stop: stop,
  restart: restart,
  gdprForgetMe: gdprForgetMe,
  disableThirdPartySharing: disableThirdPartySharing,
  initSmartBanner: initSmartBanner,
  showSmartBanner: showSmartBanner,
  hideSmartBanner: hideSmartBanner,
  __testonly__: {
    destroy: main_destroy,
    clearDatabase: _clearDatabase
  },
  __internal__: {
    restartAfterAsyncEnable: _restartAfterAsyncEnable
  }
};
/* harmony default export */ const main = (WiseTrack);
})();

__webpack_exports__ = __webpack_exports__["default"];
/******/ 	return __webpack_exports__;
/******/ })()
;
});