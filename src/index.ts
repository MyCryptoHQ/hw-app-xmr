import Transport from '@ledgerhq/hw-transport';
import { DeviceMode } from '@src/ledger-types/device';

// tslint:disable-next-line:no-default-export
export default class XMR<T> {
  private readonly transport: Transport<T>;
  private name: string;
  private readonly mode: DeviceMode;
  private readonly has_view_key: boolean;

  constructor(transport: Transport<T>) {
    this.transport = transport;
    this.name = '';
    this.mode = DeviceMode.NONE;
    this.has_view_key = false;

    transport.decorateAppAPIMethods(this, [], '');
  }

  /* ======================================================================= */
  /*                                   MISC                                  */
  /* ======================================================================= */

  public reset() {
    return this.transport.send(0x00, INS_RESET, 0x00, 0x00);
  }

  /* ======================================================================= */
  /*                              SETUP/TEARDOWN                             */
  /* ======================================================================= */

  public set_name(name: string) {
    this.name = name;
    return true;
  }

  public get_name() {
    return this.name;
  }

  public set_mode(mode: DeviceMode) {
    switch (mode) {
      case DeviceMode.TRANSACTION_CREATE_REAL:
      case DeviceMode.TRANSACTION_CREATE_FAKE:

      case DeviceMode.TRANSACTION_PARSE:
      case DeviceMode.NONE:
    }
  }
}
