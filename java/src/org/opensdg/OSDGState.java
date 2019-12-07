package org.opensdg;

public enum OSDGState {
    CLOSED,
    CONNECTING, /* State change callback is not called with this */
    CONNECTED,
    ERROR,
    PAIRING_COMPLETE,
    UNKNOWN;

    static OSDGState fromNative(int s) {
        switch (s) {
            case 0:
                return CLOSED;
            case 1:
                return CONNECTING;
            case 2:
                return CONNECTED;
            case 3:
                return ERROR;
            case 4:
                return PAIRING_COMPLETE;
            default:
                return UNKNOWN;
        }
    }
}
