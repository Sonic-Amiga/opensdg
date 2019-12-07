package org.opensdg;

public enum OSDGResult {
    NO_ERROR, // Everything is OK
    SOCKET_ERROR, // Socket I/O error
    CRYPTO_CORE_ERROR, // Sodium internal error; should never happen
    DECRYPTION_ERROR, // Sodium decryption error; likely corrupted data
    PROTOCOL_ERROR, // Some invalid data has been received
    BUFFER_EXCEEDED, // Buffer size is not enough for incoming data
    INVALID_PARAMETERS, // Invalid parameters supplied to function call
    CONNECTION_FAILED, // Unable to connect to any server
    MEMORY_ERROR, // Memory (e. g. buffers) allocation error
    CONNECTION_REFUSED, // Connection refused by peer
    TOO_MANY_CONNECTIONS, // Connection count exceeds main loop capability
    CONNECTION_CLOSED, // Connection closed by peer
    WRONG_STATE, // A request is inappropriate for current connection state
    SYSTEM_ERROR, // General OS-specific error
    UNKNOWN_ERROR;

    static OSDGResult fromNative(int res) {
        switch (res) {
            case 0:
                return NO_ERROR;
            case 1:
                return SOCKET_ERROR;
            case 2:
                return CRYPTO_CORE_ERROR;
            case 3:
                return DECRYPTION_ERROR;
            case 4:
                return PROTOCOL_ERROR;
            case 5:
                return BUFFER_EXCEEDED;
            case 6:
                return INVALID_PARAMETERS;
            case 7:
                return CONNECTION_FAILED;
            case 8:
                return MEMORY_ERROR;
            case 9:
                return CONNECTION_REFUSED;
            case 10:
                return TOO_MANY_CONNECTIONS;
            case 11:
                return CONNECTION_CLOSED;
            case 12:
                return WRONG_STATE;
            case 14:
                return SYSTEM_ERROR;
            default:
                return UNKNOWN_ERROR;
        }
    }
}
