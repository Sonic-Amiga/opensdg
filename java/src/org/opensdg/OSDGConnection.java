package org.opensdg;

public class OSDGConnection {

    private long m_Conn;

    public OSDGConnection() {
        m_Conn = OpenSDG.connection_create(this);
    }

    public void Dispose() {
        OpenSDG.connection_destroy(m_Conn);
        m_Conn = 0;
    }

    public void SetPrivateKey(byte[] key) {
        OpenSDG.set_private_key(m_Conn, key);
    }

    public byte[] GetMyPeerId() {
        return OpenSDG.get_my_peer_id(m_Conn);
    }

    public OSDGResult ConnectToDanfoss() {
        return OSDGResult.fromNative(OpenSDG.connect_to_danfoss(m_Conn));
    }

    public OSDGResult ConnectToRemote(OSDGConnection grid, byte[] peerId, String protocol) {
        return OSDGResult.fromNative(OpenSDG.connect_to_remote(grid.m_Conn, m_Conn, peerId, protocol));
    }

    public OSDGResult PairRemote(OSDGConnection grid, String otp) {
        return OSDGResult.fromNative(OpenSDG.pair_remote(grid.m_Conn, m_Conn, otp));
    }

    public OSDGResult Close() {
        return OSDGResult.fromNative(OpenSDG.connection_close(m_Conn));
    }

    public OSDGResult Send(byte[] data) {
        return OSDGResult.fromNative(OpenSDG.send_data(m_Conn, data));
    }

    public void SetBlockingMode(boolean blocking) {
        OpenSDG.set_blocking_mode(m_Conn, blocking);
    }

    public boolean GetBlockingMode() {
        return OpenSDG.get_blocking_mode(m_Conn);
    }

    public OSDGState getState() {
        return OSDGState.fromNative(OpenSDG.get_connection_state(m_Conn));
    }

    public OSDGResult getLastResult() {
        return OSDGResult.fromNative(OpenSDG.get_last_result(m_Conn));
    }

    public int getLastErrno() {
        return OpenSDG.get_last_errno(m_Conn);
    }

    public String getLastResultStr() {
        return OpenSDG.get_last_result_str(m_Conn);
    }

    public byte[] getPeerId() {
        return OpenSDG.get_peer_id(m_Conn);
    }

    public OSDGResult setPingInterval(int seconds) {
        return OSDGResult.fromNative(OpenSDG.set_ping_interval(m_Conn, seconds));
    }

    protected void onStatusChanged(OSDGState newState) {
        // Do nothing by default
    }

    protected OSDGResult onDataReceived(byte[] data) {
        return OSDGResult.NO_ERROR; // Do nothing by default
    }

    @Override
    protected void finalize() {
        if (m_Conn != 0) {
            OpenSDG.connection_destroy(m_Conn);
        }
    }

    @SuppressWarnings("unused") // Called by native code
    private void osdg_status_change_cb(int state) {
        onStatusChanged(OSDGState.fromNative(state));
    }

    @SuppressWarnings("unused") // Called by native code
    private int osdg_data_receive_cb(byte[] data) {
        return onDataReceived(data).ordinal();
    }
}
