import Transport from '@ledgerhq/hw-transport';
import {
  ChachaKey,
  CtKeyV,
  DeviceMode,
  EcdhTuple,
  EcScalar,
  Hash8,
  IAccountKeys,
  ISubaddressIndex,
  Key,
  KeyDerivation,
  KeyV,
  PublicAddress,
  PublicKey,
  SecretKey,
} from '@src/ledger-types/device';

enum RCT {
  RCTTypeNull = 0x00,
  RCTTypeFull = 0x01,
  RCTTypeSimple = 0x02,
  RCTTypeFullBulletproof = 0x03,
  RCTTypeSimpleBulletproof = 0x04,
}

type AnyFunc = (...args: any[]) => any;
interface InjectedFunctions {
  generate_chacha_key_prehashed: AnyFunc;
  derive_subaddress_public_key: AnyFunc;
  generate_key_derivation: AnyFunc;
  sc_mulsub: AnyFunc;
  // all this does is typecast crypto::private_key -> rct::key
  pk2rct: AnyFunc;
}

type ArrLike = (number | string)[] | Buffer;

interface IABPKeys {
  Aout: Key;
  Bout: Key;
  is_subaddress: boolean;
  index: number; // size_t
  Pout: Key; // search by this property
  AKout: Key;
}

class Keymap {
  private map: { [Pout: string]: IABPKeys | undefined } = {};
  public add(keys: IABPKeys) {
    if (this.map[keys.Pout]) {
      throw Error(`Cannot add key to map, Pout: ${keys.Pout} already exists`);
    }
    this.map[keys.Pout] = keys;
  }

  public find(Pout: Key) {
    return this.map[Pout];
  }

  public clear() {
    this.map = {};
  }
}

// tslint:disable:no-default-export
// tslint:disable-next-line:max-classes-per-file
export default class XMR<T> {
  private readonly transport: Transport<T>;
  private name: string;
  private mode: DeviceMode;
  private privateViewKey: string;
  private has_view_key: boolean;
  private readonly extern: InjectedFunctions;
  private readonly null_skey = this.hexString();
  private readonly key_map = new Keymap();

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
        await this.send(INS.SET_SIGNATURE_MODE, 0x01, 0x00, [0x00, mode]);
        this.mode = mode;

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

  public async generate_chacha_key(_keys: IAccountKeys): Promise<ChachaKey> {
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

    // TODO: support full 32 bit return value in the future
    // for any verification return value changes
    // but for now, we just need to check the last 4 bytes
    // to see if the last bit is 1 or not
    // const verified =
    // (verifyArr[0] << 24) |
    // (verifyArr[1] << 16) |
    // (verifyArr[2] << 8) |
    // (verifyArr[3] << 0);

    const verified = verifyArr[3];

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

  public async generate_key_image(
    pub: PublicKey,
    sec: SecretKey,
  ): Promise<PublicKey> {
    const [ki] = await this.send(
      INS.GEN_KEY_IMAGE,
      0x00,
      0x00,
      [0x00, pub, sec],
      [32],
    );
    return ki;
  }
  // #endregion DERIVATION & KEY

  /* ======================================================================= */
  /*                               TRANSACTION                               */
  /* ======================================================================= */
  // #region TRANSACTION
  public async open_tx(): Promise<SecretKey> {
    const options = 0x00;

    const account = [0x00, 0x00, 0x00, 0x00];

    // skip over R and grab encrypted r instead
    const [, enc_r] = await this.send(
      INS.OPEN_TX,
      0x01,
      0x00,
      [options, ...account],
      [32, 64],
    );

    const sec_tx_key = enc_r;

    return sec_tx_key;
  }

  public async encrypt_payment_id(
    paymentId: string,
    public_key: string,
    secret_key: string,
  ): Promise<Hash8> {
    const [enc_pid] = await this.send(
      INS.STEALTH,
      0x00,
      0x00,
      [0x00, public_key, secret_key, paymentId],
      [8],
    );
    return enc_pid;
  }

  public async decrypt_payment_id(
    paymentId: string,
    public_key: string,
    secret_key: string,
  ): Promise<Hash8> {
    return await this.encrypt_payment_id(paymentId, public_key, secret_key);
  }

  /**
   * @description store keys during construct_tx_with_tx_key to be later used during genRct ->  mlsag_prehash
   * @param {PublicKey} Aout
   * @param {PublicKey} Bout
   * @param {boolean} is_subaddress
   * @param {number} real_output_index
   * @param {Key} amount_key
   * @param {PublicKey} out_eph_public_key
   * @returns {Promise<boolean>}
   */
  public add_output_key_mapping(
    Aout: PublicKey,
    Bout: PublicKey,
    is_subaddress: boolean,
    real_output_index: number,
    amount_key: Key,
    out_eph_public_key: PublicKey,
  ): boolean {
    const shouldThrow = true;
    if (shouldThrow) {
      throw Error('Needs big integer support');
    }

    this.key_map.add({
      Aout: this.extern.pk2rct(Aout),
      Bout: this.extern.pk2rct(Bout),
      is_subaddress,
      index: real_output_index,
      Pout: this.extern.pk2rct(out_eph_public_key),
      AKout: amount_key,
    });

    return true;
  }

  public async ecdhEncode(
    unmasked: EcdhTuple,
    AKout: SecretKey,
  ): Promise<EcdhTuple> {
    // AKout -> Amount key for output
    // AKout = encrypted private derivation data computed during the processing of output transaction keys
    // derivation data  = generate_key_derivation(Kv (recipent view public key), r (tx_key) ) = r.Kv
    // scalar = hash_to_scalar(Kv.r)
    // AKout = rct::sk2rct(Hn(rKv)) where rct::sk2rct just typecasts type crypto::secret_key to rct::key
    const [blindAmount, blindMask] = await this.send(
      INS.BLIND,
      0x00,
      0x00,
      [0x00, AKout, unmasked.mask, unmasked.amount],
      [32, 64],
    );

    return { amount: blindAmount, mask: blindMask };
  }

  public async ecdhDecode(
    masked: EcdhTuple,
    AKout: SecretKey,
  ): Promise<EcdhTuple> {
    const [unmaskedAmount, unmaskedMask] = await this.send(
      INS.UNBLIND,
      0x00,
      0x00,
      [0x00, AKout, masked.mask, masked.amount],
      [32, 64],
    );
    return { amount: unmaskedAmount, mask: unmaskedMask };
  }

  public async mlsag_prehash(
    blob: string,
    inputs_size: number, // 64 bits
    outputs_size: number, // 64 bits
    hashes: KeyV,
    outPk: CtKeyV,
  ): Promise<Key> {
    const shouldThrow = true;
    if (shouldThrow) {
      throw Error('Needs big integer support');
    }

    const data = Buffer.from(blob, 'hex');

    const options = inputs_size === 0 ? 0x00 : 0x80;
    const type = data[0];
    const txnFee: number[] = [];
    let data_offset = 1;

    while (data[data_offset] & 0x80) {
      txnFee.push(data[data_offset], 16);
      data_offset += 1;
    }
    // monero_apdu_mlsag_prehash_init p2 === 1
    await this.send(INS.VALIDATE, 0x01, 0x01, [
      options,
      type,
      ...txnFee,
      data[data_offset],
    ]);

    data_offset += 1;

    // monero_apdu_mlsag_prehash_init p2 > 1
    // pseudoOuts
    if (type === RCT.RCTTypeSimple || type === RCT.RCTTypeSimpleBulletproof) {
      for (let i = 0; i < inputs_size; i++) {
        const ins = INS.VALIDATE;
        const p1 = 0x01;
        const p2 = i + 0x02;
        const opts = i === inputs_size - 1 ? 0x00 : 0x80;
        // slice 32 bytes starting from data_offset
        const pseudoOut = data
          .slice(data_offset, data_offset + 32)
          .toString('hex');

        await this.send(ins, p1, p2, [opts, pseudoOut]);

        data_offset += 32;
      }
    }

    // ======  Aout, Bout, AKout, C, v, k ======
    // where k is the mask
    // and v is the amount
    // Aout, Bout is the receiver main  view/spend public keys
    // keccak: 2nd group generator, such H = h.G and keccak is unknown
    // C is the commitment to v where Cv = k.G + v.H
    // monero_apdu_mlsag_prehash_update
    let kv_offset = data_offset;
    let C_offset = kv_offset + 32 * 2 * outputs_size;
    for (let i = 0; i < outputs_size; i++) {
      const outKeys = this.key_map.find(outPk[i].dest);
      if (!outKeys) {
        throw Error(`Pout not found: ${outPk[i].dest} `);
      }

      const ins = INS.VALIDATE;
      const p1 = 0x02;
      const p2 = i + 0x01;
      const opts = i === outputs_size - 1 ? 0x00 : 0x80;
      const data_buf: any[] = [
        opts,
        outKeys.is_subaddress,
        outKeys.Aout,
        outKeys.Bout,
        outKeys.AKout,
      ];

      // C
      data_buf.push(data.slice(C_offset, C_offset + 32).toString('hex'));
      C_offset += 32;

      // k
      data_buf.push(data.slice(kv_offset, kv_offset + 32).toString('hex'));
      kv_offset += 32;

      //v
      data_buf.push(data.slice(kv_offset, kv_offset + 32).toString('hex'));
      kv_offset += 32;

      await this.send(ins, p1, p2, data_buf);
    }

    // ======   C[], message, proof======
    let _i = 0;
    C_offset = kv_offset;
    for (_i = 0; _i < outputs_size; _i++) {
      const ins = INS.VALIDATE;
      const p1 = 0x03;
      const p2 = _i + 0x01;
      const opts = 0x80;

      // C
      const C = data.slice(C_offset, C_offset + 32).toString('hex');
      C_offset += 32;

      await this.send(ins, p1, p2, [opts, C]);
    }

    const [prehash] = await this.send(
      INS.VALIDATE,
      0x03,
      _i + 0x01,
      [0x00, hashes[0], hashes[2]],
      [32],
    );
    return prehash;
  }
  /**
   *
   * @description Generate the matrix ring parameters
   * @param {Key} H
   * @param {Key} xx
   * @returns {Promise<{ a: Key, aG: Key, aHP: Key, II: Key }>}
   * @memberof Device
   */
  public async mlsag_prepare(
    H: Key,
    xx: Key,
  ): Promise<{ a: Key; aG: Key; aHP: Key; II: Key }>;

  /**
   *
   * @description Generate the matrix ring parameters
   * @returns {Promise<{ a: Key, aG: Key }>}
   * @memberof Device
   */
  public async mlsag_prepare(): Promise<{ a: Key; aG: Key }>;

  public async mlsag_prepare(H?: Key, xx?: Key) {
    if (!H || !xx) {
      const [a, aG] = await this.send(INS.MLSAG, 0x01, 0x00, [0x00], [32, 64]);
      return { a, aG };
    } else {
      // a -> alpha -> one time secret key for tx
      // aG -> alpha.G -> one time public key for tx
      const [a, aG, aHP, II] = await this.send(
        INS.MLSAG,
        0x01,
        0x00,
        [0x00, H, xx],
        [32, 64, 96, 128],
      );
      return { a, aG, aHP, II };
    }
  }

  public async mlsag_hash(long_message: KeyV): Promise<Key> {
    // cnt is size_t
    const cnt = long_message.length;
    let res: string = '';
    for (let i = 0; i < cnt; i++) {
      [res] = await this.send(
        INS.MLSAG,
        0x02,
        i + 0x01,
        [i === cnt - 1 ? 0x00 : 0x80, long_message[i]],
        [32],
      );
    }

    if (!res) {
      throw Error('Return value of last exchange is empty string');
    }

    return res;
  }

  public async mlsag_sign(
    c: Key,
    xx: KeyV,
    alpha: KeyV,
    rows: number,
    dsRows: number,
    ss: KeyV,
  ): Promise<KeyV> {
    if (dsRows >= rows) {
      throw Error('dsRows greater than rows');
    }
    if (xx.length !== rows) {
      throw Error('xx size does not match rows');
    }
    if (alpha.length !== rows) {
      throw Error('alpha size does not match rows');
    }
    if (ss.length !== rows) {
      throw Error('ss size does not match rows');
    }

    const ssRet: KeyV = [];

    for (let j = 0; j < dsRows; j++) {
      // ss[j]
      const [ssj] = await this.send(
        INS.MLSAG,
        0x03,
        j + 1,
        [j === dsRows - 1 ? 0x80 : 0x00, xx[j], alpha[j]],
        [32],
      );
      ssRet.push(ssj);
    }

    for (let j = dsRows; j < rows; j++) {
      // sc_mulsub(const unsigned char *a, const unsigned char *b, const unsigned char *c)  -> unsigned char *s
      // c - a.b mod l
      ssRet[j] = this.extern.sc_mulsub(c, xx[j], alpha[j]);
    }

    return ssRet;
  }

  public async close_tx(): Promise<boolean> {
    await this.send(INS.CLOSE_TX, 0x00, 0x00, [0x00]);
    return true;
  }

  // #endregion TRANSACTION

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
    return Buffer.alloc(length, byteValue, 'hex').toString('hex');
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
    function sliceBufToHex(buf: Buffer, start: number, end: number) {
      // initialize a buffer of required size
      // so we dont slice out of bounds if returned bytes
      // is less than slice size

      const zeroBuf = Buffer.alloc(end - start);
      // copy data into zero buffer
      buf.copy(zeroBuf);
      // slice
      return zeroBuf.slice(start, end).toString('hex');
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
