import Transport from '@ledgerhq/hw-transport';
import {
  ChachaKey,
  DeviceMode,
  EcScalar,
  IAccountKeys,
  ISubaddressIndex,
  Key,
  KeyDerivation,
  PublicAddress,
  PublicKey,
  SecretKey,
} from '@src/ledger-types/device';

type AnyFunc = (...args: any[]) => any;
interface InjectedFunctions {
  generate_chacha_key_prehashed: AnyFunc;
  derive_subaddress_public_key: AnyFunc;
  generate_key_derivation: AnyFunc;
}

type ArrLike = (number | string)[] | Buffer;

// tslint:disable-next-line:no-default-export
export default class XMR<T> {
  private readonly transport: Transport<T>;
  private name: string;
  private mode: DeviceMode;
  private privateViewKey: string;
  private has_view_key: boolean;
  private readonly extern: InjectedFunctions;
  private readonly null_skey = this.hexString();
  constructor(transport: Transport<T>, injectedFuncs: InjectedFunctions) {
    this.transport = transport;
    this.name = '';
    this.mode = DeviceMode.NONE;
    this.has_view_key = false;
    this.privateViewKey = this.hexString();
    this.extern = injectedFuncs;
    transport.decorateAppAPIMethods(this, [], '');
  }

  /* ======================================================================= */
  /*                                   MISC                                  */
  /* ======================================================================= */
  // #region  MISC
  public reset() {
    return this.send(INS.RESET, 0x00, 0x00);
  }
  // #endregion  MISC

  /* ======================================================================= */
  /*                              SETUP/TEARDOWN                             */
  /* ======================================================================= */
  // #region  SETUP/TEARDOWN
  public set_name(name: string) {
    this.name = name;
    return true;
  }

  public get_name() {
    return this.name;
  }

  public async set_mode(mode: DeviceMode) {
    switch (mode) {
      case DeviceMode.TRANSACTION_CREATE_REAL:
      case DeviceMode.TRANSACTION_CREATE_FAKE:
        this.mode = mode;
        await this.send(INS.SET_SIGNATURE_MODE, 0x01, 0x00, [0x00, mode]);
        break;

      case DeviceMode.TRANSACTION_PARSE:
      case DeviceMode.NONE:
        this.mode = mode;
        break;
      default:
        throw Error(
          `device_ledger::set_mode(unsigned int mode): invalid mode ${mode}`,
        );
    }

    console.log(`Switched to mode: ${mode}`);
    return true;
  }

  // #endregion  SETUP/TEARDOWN

  /* ======================================================================= */
  /*                             WALLET & ADDRESS                            */
  /* ======================================================================= */
  // #region WALLET & ADDRESS

  public async get_public_address(): Promise<PublicAddress> {
    const [view_public_key, spend_public_key] = await this.send(
      INS.GET_KEY,
      0x01,
      0x00,
      undefined,
      [32, 64],
    );

    return {
      view_public_key,
      spend_public_key,
    };
  }

  /**
   *
   * @description Retrives the secret view key if the user allows the export
   * @returns Fake view and send private key
   * @memberof XMR
   */
  public async get_secret_keys() {
    // secret keys are represented as fake keys on the wallet side
    // because secret keys are always in possesion of the ledger device
    const vkey = this.hexString();
    const skey = this.hexString(0xff);

    const [viewKey] = await this.send(INS.GET_KEY, 0x02, 0x00, [0x00], [32]);
    this.privateViewKey = viewKey;
    this.has_view_key = !this.is_fake_view_key(this.privateViewKey);

    return [vkey, skey];
  }

  public async generate_chacha_key(keys: IAccountKeys): Promise<ChachaKey> {
    const [prekey] = await this.send(
      INS.GET_CHACHA8_PREKEY,
      0x00,
      0x00,
      [0x00],
      [200],
    );
    return this.extern.generate_chacha_key_prehashed(prekey);
  }

  // #endregion WALLET & ADDRESS

  /* ======================================================================= */
  /*                               SUB ADDRESS                               */
  /* ======================================================================= */
  // #region SUB ADDRESS

  /**
   *
   * @description Although the logic for this function is fully implemented,
   * it will throw regardless of input, because output_index can be >32 bits
   * but the number type only supports 32 bit integers. So this will stay as permanently
   * throwing until a big integer library is decided on.
   * @param {PublicKey} pub
   * @param {KeyDerivation} derivation
   * @param {number} output_index
   * @returns {Promise<PublicKey>}
   * @memberof XMR
   */
  public async derive_subaddress_public_key(
    pub: PublicKey,
    derivation: KeyDerivation,
    output_index: number,
  ): Promise<PublicKey> {
    const shouldThrow = true;
    if (shouldThrow) {
      throw Error('Needs big integer support');
    }

    if (this.mode === DeviceMode.TRANSACTION_PARSE && this.has_view_key) {
      //If we are in TRANSACTION_PARSE, the given derivation has been retrieved decrypted (wihtout the help
      //of the device), so continue that way.
      return this.extern.derive_subaddress_public_key(
        pub,
        derivation,
        output_index,
      );
    } else {
      const [derived_pub] = await this.send(
        INS.DERIVE_SUBADDRESS_PUBLIC_KEY,
        0x00,
        0x00,
        [
          0x00,
          pub,
          derivation,
          output_index >> 24,
          output_index >> 16,
          output_index >> 8,
          output_index >> 0,
        ],
        [32],
      );

      return derived_pub;
    }
  }

  public async get_subaddress_spend_public_key(
    keys: IAccountKeys,
    index: ISubaddressIndex,
  ): Promise<PublicKey> {
    if (index.isZero()) {
      return keys.m_account_address.spend_public_key;
    }

    // decompress index, taking 4+4 bytes
    const [D] = await this.send(
      INS.GET_SUBADDRESS_SPEND_PUBLIC_KEY,
      0x00,
      0x00,
      [0x00, index.major, index.minor],
      [32],
    );
    return D;
  }

  public async get_subaddress_spend_public_keys(
    keys: IAccountKeys,
    account: number,
    begin: number,
    end: number,
  ) {
    const pkeys: PublicKey[] = [];
    for (let index = begin; index < end; index++) {
      pkeys.push(
        await this.get_subaddress_spend_public_key(keys, {
          major: account,
          minor: index,
          isZero: () => false, // need to impl
        }),
      );
    }
    return pkeys;
  }

  public async get_subaddress(
    keys: IAccountKeys,
    index: ISubaddressIndex,
  ): Promise<PublicAddress> {
    if (index.isZero()) {
      return keys.m_account_address;
    }
    const [view_public_key, spend_public_key] = await this.send(
      INS.GET_SUBADDRESS,
      0x00,
      0x00,
      [0x00, index.major, index.minor],
      [32, 64],
    );
    return { view_public_key, spend_public_key };
  }

  public async get_subaddress_secret_key(
    sec: SecretKey,
    index: ISubaddressIndex,
  ): Promise<SecretKey> {
    const [sub_sec] = await this.send(
      INS.GET_SUBADDRESS_SECRET_KEY,
      0x00,
      0x00,
      [0x00, sec, index.major, index.minor],
      [32],
    );
    return sub_sec;
  }
  // #endregion SUB ADDRESS

  // #region DERIVATION & KEY
  public async verify_keys(secret_key: SecretKey, public_key: PublicKey) {
    const verifyArr = await this.send(
      INS.VERIFY_KEY,
      0x00,
      0x00,
      [0x00, secret_key, public_key],
      [1, 2, 3, 4],
    ).then(arr => arr.map(str => parseInt(str, 16)));

    const verified =
      (verifyArr[0] << 24) |
      (verifyArr[1] << 16) |
      (verifyArr[2] << 8) |
      (verifyArr[3] << 0);

    return verified === 1;
  }

  public async scalarmultKey(P: Key, a: Key): Promise<Key> {
    const [aP] = await this.send(
      INS.SECRET_SCAL_MUL_KEY,
      0x00,
      0x00,
      [0x00, P, a],
      [32],
    );
    return aP;
  }

  public async scalarmultBase(a: Key): Promise<Key> {
    const [aG] = await this.send(
      INS.SECRET_SCAL_MUL_BASE,
      0x00,
      0x00,
      [0x00, a],
      [32],
    );
    return aG;
  }

  public async sc_secret_add(a: SecretKey, b: SecretKey) {
    const [r] = await this.send(
      INS.SECRET_KEY_ADD,
      0x00,
      0x00,
      [0x00, a, b],
      [32],
    );
    return r;
  }

  public async generate_keys(recovery_key: SecretKey, recover: boolean) {
    if (recover || recovery_key) {
      throw Error(
        'Ledger device method generate_keys does not support recover',
      );
    }
    const [pub, sec] = await this.send(
      INS.GENERATE_KEYPAIR,
      0x00,
      0x00,
      [0x00],
      [32, 64],
    );

    return [pub, sec];
  }

  public async generate_key_derivation(
    pub: PublicKey,
    sec: SecretKey,
  ): Promise<KeyDerivation> {
    if (this.mode === DeviceMode.TRANSACTION_PARSE && this.has_view_key) {
      // When a derivation is requested in PARSE mode and the view key is available,
      // Perform the derivation via extern library and return the derivation unencrypted
      console.log('generate_key_derivation  : PARSE mode with known viewkey');

      //Note derivation in PARSE mode can only happen with viewkey, so assert it! (?)
      console.assert(
        this.is_fake_view_key(sec),
        'Derivation in PARSE mode can only happen with viewkey',
      );
      const derivation = this.extern.generate_key_derivation(
        pub,
        this.privateViewKey,
      );
      return derivation;
    } else {
      const [derivation] = await this.send(
        INS.GEN_KEY_DERIVATION,
        0x00,
        0x00,
        [0x00, pub, sec],
        [32],
      );
      return derivation;
    }
  }

  public async conceal_derivation(
    derivation: KeyDerivation,
    tx_pub_key: PublicKey,
    additional_tx_pub_keys: PublicKey[],
    main_derivation: KeyDerivation,
    additional_derivations: KeyDerivation[],
  ) {
    let pubKey: string | undefined;
    if (derivation === main_derivation) {
      pubKey = tx_pub_key;
      console.log('conceal derivation with main tx pub key');
    } else {
      console.warn(
        'conceal_derivation NOTE: if size of additional_derivations > Number.MAX_INTEGER, then we have a problem',
      );
      const derivationIdx = additional_derivations.indexOf(derivation);
      if (derivationIdx !== -1) {
        pubKey = additional_tx_pub_keys[derivationIdx];
      }
      console.log('conceal derivation with additional tx pub key');
    }
    if (pubKey === undefined) {
      throw Error('Mismatched derivation on scan info');
    }

    return this.generate_key_derivation(pubKey, this.null_skey);
  }

  public async derivation_to_scalar(
    derivation: KeyDerivation,
    output_index: number,
  ): Promise<EcScalar> {
    const shouldThrow = true;
    if (shouldThrow) {
      throw Error('Needs big integer support');
    }

    const [scalar] = await this.send(
      INS.DERIVATION_TO_SCALAR,
      0x00,
      0x00,
      [
        0x00,
        derivation,
        output_index >> 24,
        output_index >> 16,
        output_index >> 8,
        output_index >> 0,
      ],
      [32],
    );

    return scalar;
  }

  public async derive_secret_key(
    derivation: KeyDerivation,
    output_index: number,
    sec: SecretKey,
  ): Promise<SecretKey> {
    const shouldThrow = true;
    if (shouldThrow) {
      throw Error('Needs big integer support');
    }

    const [derivedSec] = await this.send(
      INS.DERIVE_SECRET_KEY,
      0x00,
      0x00,
      [
        0x00,
        derivation,
        output_index >> 24,
        output_index >> 16,
        output_index >> 8,
        output_index >> 0,
        sec,
      ],
      [32],
    );

    return derivedSec;
  }

  public async derive_public_key(
    derivation: PublicKey,
    output_index: number,
    pub: PublicKey,
  ): Promise<PublicKey> {
    const [derived_pub] = await this.send(
      INS.DERIVE_PUBLIC_KEY,
      0x00,
      0x00,
      [
        0x00,
        derivation,
        output_index >> 24,
        output_index >> 16,
        output_index >> 8,
        output_index >> 0,
        pub,
      ],
      [32],
    );
    return derived_pub;
  }

  public async secret_key_to_public_key(sec: SecretKey): Promise<PublicKey> {
    const [pub] = await this.send(
      INS.SECRET_KEY_TO_PUBLIC_KEY,
      0x00,
      0x00,
      [0x00, sec],
      [32],
    );
    return pub;
  }
  // #endregion DERIVATION & KEY

  // #region Internal private methods
  private is_fake_view_key(viewKey: string) {
    return viewKey === this.hexString();
  }

  /**
   * @description Create a hex string by filling a array with the supplied value
   * and then converting it to a byte buffer, then to a string
   * @private
   * @param {number} [byteValue=0x00]
   * @param {number} [length=32]
   * @returns
   * @memberof XMR
   */
  private hexString(byteValue: number = 0x00, length: number = 32) {
    return Buffer.from(Array(length).fill(byteValue)).toString('hex');
  }

  /**
   *
   * @description Generates hex string slices from a buffer
   * @private
   * @param {Buffer} buffer to buffer to slice and convert into hex strings
   * @param {number[]} endingIndicesToSliceAt An array of ending indices to slice at
   *
   * Ex. If [32,64] is supplied, the following slices will be returned:
   *
   * [buffer.slice(0,32).toString("hex"),  buffer.slice(32,64).toString("hex")]
   * @memberof XMR
   */
  private bufferToSlicedHexString(
    buffer: Buffer,
    endingIndicesToSliceAt: number[],
  ) {
    function sliceBufToHex(buf: Buffer, start?: number, end?: number) {
      return buf.slice(start, end).toString('hex');
    }

    return endingIndicesToSliceAt.reduce(
      (prev, currEndSliceIdx, idx, slicingIndices) => [
        ...prev,
        sliceBufToHex(
          buffer,
          !idx ? 0 : slicingIndices[idx - 1],
          currEndSliceIdx,
        ),
      ],
      [],
    );
  }

  private arrLikeToBuf(arrLike: ArrLike) {
    return Array.isArray(arrLike) ? Buffer.from(arrLike) : arrLike;
  }

  private async send(
    ins: INS,
    p1: number,
    p2: number,
    data?: ArrLike | undefined,
  ): Promise<undefined>;

  private async send(
    ins: INS,
    p1: number,
    p2: number,
    data: ArrLike | undefined,
    endingIndicesToSliceAt: number[],
  ): Promise<string[]>;

  // #endregion Internal private methods

  private async send(
    ins: INS,
    p1: number,
    p2: number,
    data?: ArrLike | undefined,
    endingIndicesToSliceAt?: number[],
  ) {
    const buf = await this.transport.send(
      0x00,
      ins,
      p1,
      p2,
      data ? this.arrLikeToBuf(data) : undefined,
    );
    if (!endingIndicesToSliceAt) {
      return;
    } else {
      return this.bufferToSlicedHexString(buf, endingIndicesToSliceAt);
    }
  }
}
