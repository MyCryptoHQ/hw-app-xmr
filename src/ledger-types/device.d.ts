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
   *
   * @param {string} pub
   * @param {*} deriviation
   * @param {number} output_index
   * @returns {string} Derived public key Ks,i
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
   * @param {number} index
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
   * @description Get a subaddress Ks,i
   * @param {IAccountKeys} keys
   * @param {number} index
   * @returns {PublicAddress}
   * @memberof Device
   */
  get_subaddress(keys: IAccountKeys, index: number): PublicAddress;

  /**
   *
   * @description Get a subaddress secret key
   * @param {SecretKey} sec
   * @param {number} index
   * @returns {SecretKey}
   * @memberof Device
   */
  get_subaddress_secret_key(sec: SecretKey, index: number): SecretKey;
}
