export enum DeviceMode {
  TRANSACTION_CREATE_REAL,
  TRANSACTION_CREATE_FAKE,
  TRANSACTION_PARSE,
  NONE,
}

// to later be converted to opaque types
type PublicAddress = string;
type SecretKey = string;
type SecretKeys = [string, string];
type ChachaKey = string;
type PublicSpendKey = string;
type PublicKey = string;
type KeyPair = [string, string];
type EcScalar = string;
interface EcdhTuple {
  mask: string;
  amount: string;
}
type Key = PublicKey | SecretKey;
// cryptonote_basic
interface IAccountKeys {
  m_account_address: string;
  m_spend_secret_key: string;
  m_view_secret_key: string;
  m_device: Device;
}

// device.hpp
// let kv, ks = private view and spend keys
// let Kv, Ks = public view and spend keys

export interface Device {
  /* ======================================================================= */
  /*                              SETUP/TEARDOWN                             */
  /* ======================================================================= */
  set_name(name: string): boolean;
  get_name(): boolean;
  set_mode(mode: DeviceMode): boolean;

  /* ======================================================================= */
  /*                             WALLET & ADDRESS                            */
  /* ======================================================================= */

  /**
   *
   * @description Get the public address (Kv + Ks) of an account
   * @returns {PublicAddress}
   * @memberof Device
   */
  get_public_address(): PublicAddress;

  /**
   *
   * @description Get secret keys [kv, ks] of an account
   * @returns {SecretKeys}
   * @memberof Device
   */
  get_secret_keys(): SecretKeys;

  /**
   *
   * @description Generate chacha key from kv and ks
   * @returns {boolean}
   * @memberof Device
   */
  generate_chacha_key(keys: IAccountKeys): ChachaKey;

  /* ======================================================================= */
  /*                               SUB ADDRESS                               */
  /* ======================================================================= */

  /**
   *
   * @description Derives a subaddress public key
   * @param {string} pub K0
   * @param {*} deriviation rKv
   * @param {number} output_index t
   * @returns {string} K0 - derivation_to_scalar(rkv,t).G
   * @memberof Device
   */
  derive_subaddress_public_key(
    pub: string,
    deriviation: any,
    output_index: number,
  ): string;

  /**
   *
   *
   * @param {SecretKeys} keys Secret keypair [kv, ks]
   * @param {number} index t
   * @returns {string} Ks,i
   * @memberof Device
   */
  get_subaddress_spend_public_key(keys: IAccountKeys, index: number): string;

  /**
   *
   * @description Get an array of public subaddress spend keys Ks,i[]
   * @param {IAccountKeys} keys
   * @param {number} account
   * @param {number} begin
   * @param {number} end
   * @returns {PublicSpendKey[]}
   * @memberof Device
   */
  get_subaddress_spend_public_keys(
    keys: IAccountKeys,
    account: number,
    begin: number,
    end: number,
  ): PublicSpendKey[];

  /**
   *
   * @description Get a subaddress (Kv,i + Ks,i)
   * @param {IAccountKeys} keys
   * @param {number} index
   * @returns {PublicAddress}
   * @memberof Device
   */
  get_subaddress(keys: IAccountKeys, index: number): PublicAddress;

  /**
   *
   * @description Get a subaddress secret key `Hn(kv, i)`
   * @param {SecretKey} sec The secret key to derive the sub secret key from
   * @param {number} index
   * @returns {SecretKey}
   * @memberof Device
   */
  get_subaddress_secret_key(sec: SecretKey, index: number): SecretKey;

  /* ======================================================================= */
  /*                            DERIVATION & KEY                             */
  /* ======================================================================= */

  /**
   *
   * @description Verifies that a keypair [k, K] are valid
   * @param {SecretKey} secretKey
   * @param {PublicKey} publicKey
   * @returns {boolean}
   * @memberof Device
   */
  verify_keys(secretKey: SecretKey, publicKey: PublicKey): boolean;

  /**
   * @description Variable-base scalar multiplications for some integer a, and point P: aP (VBSM)
   * @param {string} P
   * @param {string} a
   * @returns {string} aP
   * @memberof Device
   */
  scalarmultKey(P: string, a: string): string;

  /**
   * @description Known-base scalar multiplications for some integer a: aG (KBSM)
   * @param {string} a
   * @returns {string} aG
   * @memberof Device
   */
  scalarmultBase(a: string): string;

  /**
   *
   * @description Scalar addition (each private key is a scalar) a + b = r
   * @param {string} a
   * @param {string} b
   * @returns {string} r
   * @memberof Device
   */
  sc_secret_add(a: string, b: string): string;

  /**
   * @description Generates a keypair (R, r), leave recovery key undefined for a random key pair
   * @param {SecretKey} recoveryKey
   * @returns {KeyPair}
   * @memberof Device
   */
  generate_keys(recoveryKey: SecretKey | undefined): KeyPair;

  /**
   *
   * @description Generates a key deriviation,
   * can be used to generate ephemeral_(pub|sec) which is the one-time keypair
   * @param {PublicKey} pub Ex. rG, a transaction public key
   * @param {SecretKey} sec Ex. kv, a secret view key
   * @returns {string} Derived Key Ex. rG.kv -> rKv
   * @memberof Device
   */
  generate_key_derivation(pub: PublicKey, sec: SecretKey): PublicKey;

  /**
   * @description Conceals a deriviation, used when a clear text deriviation needs to be encrypted so it can
   * later be used by other device methods since they only allow encrypted deriviations as input
   * If the main deriviation matches the deriviation, then the concealed deriviation of the tx_pub_key is returned,
   * otherwise additional_deriviations is scanned through for a matching deriviation, then the matching index is used to return the concealed
   * additional_tx_pub_keys at the matching index
   * @link https://github.com/monero-project/monero/pull/3591
   * @see 5.3.1 Zero-to-monero
   * Used when scanning txs to see if any txs are directed towards the users address
   * @ignore subaddresses
   * @param {PublicKey} deriviation e.g rKv
   * @param {PublicKey} tx_pub_key
   * @param {PublicKey[]} additional_tx_pub_keys used for multi-destination transfers involving one or more subaddresses
   * @param {PublicKey} main_deriviation
   * @param {PublicKey[]} additional_derivations used for multi-destination transfers involving one or more subaddresses
   * @returns {PublicKey}
   * @memberof Device
   */
  conceal_derivation(
    deriviation: PublicKey,
    tx_pub_key: PublicKey,
    additional_tx_pub_keys: PublicKey[],
    main_deriviation: PublicKey,
    additional_derivations: PublicKey[],
  ): PublicKey;

  /**
   *
   * @description Transforms a derivation to a scalar based on an index
   * Used for multi output transactions and subaddresses
   * @param {PublicKey} deriviation e.g rKv
   * @param {number} output_index t
   * @returns {EcScalar} e.g Hn(rKvt, t)
   * @memberof Device
   */
  derivation_to_scalar(deriviation: PublicKey, output_index: number): EcScalar;

  /**
   *
   * @description Derive a secret key
   * Used to derive an emphemeral (one-time) secret key at index t which then can be used to spend an output or, generate a key image (kHp(K)) when combined
   * when the corresponding public key
   * @see 5.2.1 Zero-to-monero
   * @param {PublicKey} deriviation e.g rKv
   * @param {number} output_index e.g t
   * @param {SecretKey} sec e.g ks, a private spend key
   * @returns {SecretKey} e.g k0, where k0 = Hn(rKv,t) + ks
   * @memberof Device
   */
  derive_secret_key(
    deriviation: PublicKey,
    output_index: number,
    sec: SecretKey,
  ): SecretKey;

  /**
   *
   * @description Derive a public key
   * Used to derive an emphemeral (one-time) public key at index t which then can be used check if a transaction belongs to
   * the public key, or generate a key image (kHp(K)) when combined with the corresponding private key
   * @see 5.2.1 Zero-to-monero
   * @param {PublicKey} deriviation e.g rKv
   * @param {number} output_index e.g t
   * @param {SecretKey} pub e.g Ks, a public spend key
   * @returns {SecretKey} e.g k0, where k0 = Hn(rKv,t) + Ks
   * @memberof Device
   */
  derive_public_key(
    deriviation: PublicKey,
    output_index: number,
    pub: PublicKey,
  ): PublicKey;

  /**
   *
   * @description Generates a public key from a secret key
   * @param {SecretKey} sec e.g k
   * @returns {PublicKey} e.g K where K = kG
   * @memberof Device
   */
  secret_key_to_public_key(sec: SecretKey): PublicKey;

  /**
   *
   * @description Generates key image kHp(K)
   * @param {PublicKey} pub K
   * @param {SecretKey} sec k
   * @returns {PublicKey} kHp(K)
   * @memberof Device
   */
  generate_key_image(pub: PublicKey, sec: SecretKey): PublicKey;

  /* ======================================================================= */
  /*                               TRANSACTION                               */
  /* ======================================================================= */

  /**
   *
   * @description First step of creating a transaction, returns the secret tx key
   * @returns {SecretKey}
   * @memberof Device
   */
  open_tx(): SecretKey;

  /**
   *
   * @description Encrypt payment id
   * @param {string} paymentId
   * @param {string} public_key Kv
   * @param {string} secret_key r
   * @returns {string} encrypted payment id = XOR (Hn( generate_key_deriviation(r, Kv) , ENCRYPTED_PAYMENT_ID_TAIL), paymentId)
   * @memberof Device
   */
  encrypt_payment_id(
    paymentId: string,
    public_key: string,
    secret_key: string,
  ): string;

  /**
   *
   * @description Decrypt payment id
   * @param {string} paymentId
   * @param {string} public_key
   * @param {string} secret_key
   * @returns {string} Decrypted payment id = encrypt_payment_id(payment_id, public_key, secret_key) since its a XOR operation
   * @memberof Device
   */
  decrypt_payment_id(
    paymentId: string,
    public_key: string,
    secret_key: string,
  ): string;

  /**
   *
   * @description Elliptic Curve Diffie Helman: encodes the amount b and mask a
   * where C= aG + bH
   * @param {EcdhTuple} unmasked The unmasked ecdh tuple to encode using the shared secret
   * @param {string} sharedSec e.g sharedSec = derivation_to_scalar(rKv,t)
   * @returns {EcdhTuple}
   * @memberof Device
   */
  ecdhEncode(unmasked: EcdhTuple, sharedSec: SecretKey): EcdhTuple;

  /**
   *
   * @description Elliptic Curve Diffie Helman: decodes the amount b and mask a
   * where C= aG + bH
   * @param {EcdhTuple} masked The masked ecdh tuple to decude using the shared secret
   * @param {SecretKey} sharedSec e.g sharedSec = derivation_to_scalar(rKv,t)
   * @returns {EcdhTuple}
   * @memberof Device
   */
  ecdhDecode(masked: EcdhTuple, sharedSec: SecretKey): EcdhTuple;

  /**
   * @description store keys during construct_tx_with_tx_key to be later used during genRct ->  mlsag_prehash
   * @param {PublicKey} aOut
   * @param {PublicKey} Bout
   * @param {boolean} is_subaddress
   * @param {number} real_output_index
   * @param {Key} amount_key
   * @param {PublicKey} out_eph_public_key
   * @returns {boolean}
   * @memberof Device
   */
  add_output_key_mapping(
    aOut: PublicKey,
    Bout: PublicKey,
    is_subaddress: boolean,
    real_output_index: number,
    amount_key: Key,
    out_eph_public_key: PublicKey,
  ): boolean;
}
