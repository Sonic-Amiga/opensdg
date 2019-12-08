#include "org_opensdg_OpenSDG.h"
#include "opensdg.h"

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    return JNI_VERSION_1_4;
}

static int initialized = 0;

JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    if (!initialized)
        return;

    osdg_shutdown();
    initialized = 0;
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_init(JNIEnv *env, jclass cl)
{
    osdg_result_t res = osdg_init();

    initialized = (res == osdg_no_error);
    return res;
}

static jbyte *getNativeKey(JNIEnv *env, jbyteArray key)
{
    if ((*env)->GetArrayLength(env, key) != sizeof(osdg_key_t))
        return NULL;

    return (*env)->GetByteArrayElements(env, key, NULL);
}

JNIEXPORT void JNICALL Java_org_opensdg_OpenSDG_SetPrivateKey(JNIEnv *env, jclass cl, jbyteArray key)
{
    jbyte *nativeKey = getNativeKey(env, key);
    
    // FIXME : Handle parameter error
    osdg_set_private_key(nativeKey);
    (*env)->ReleaseByteArrayElements(env, key, nativeKey, 0);
}

static jbyteArray makeJavaKey(JNIEnv *env, const osdg_key_t nativeKey)
{
    jbyteArray key = (*env)->NewByteArray(env, sizeof(osdg_key_t));

    (*env)->SetByteArrayRegion(env, key, 0, sizeof(osdg_key_t), nativeKey);
    return key;
}

JNIEXPORT jbyteArray JNICALL Java_org_opensdg_OpenSDG_GetMyPeerId(JNIEnv *env, jclass cl)
{
    return makeJavaKey(env, osdg_get_my_peer_id());
}

JNIEXPORT jbyteArray JNICALL Java_org_opensdg_OpenSDG_CreatePrivateKey(JNIEnv *env, jclass cl)
{
    osdg_key_t nativeKey;

    osdg_create_private_key(nativeKey);
    return makeJavaKey(env, nativeKey);
}

JNIEXPORT jlong JNICALL Java_org_opensdg_OpenSDG_connection_1create(JNIEnv *env, jclass cl, jobject jConn)
{
    osdg_connection_t conn = osdg_connection_create();

    if (conn)
        osdg_set_user_data(conn, (void *)jConn);

    return (jlong)conn;
}

JNIEXPORT void JNICALL Java_org_opensdg_OpenSDG_connection_1destroy(JNIEnv *env, jclass cl, jlong conn)
{
    osdg_connection_destroy((osdg_connection_t)conn);
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_connect_1to_1danfoss(JNIEnv *env, jclass cl, jlong conn)
{
    return osdg_connect_to_danfoss((osdg_connection_t)conn);
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_connect_1to_1remote(JNIEnv *env, jclass cl, jlong grid, jlong peer, jbyteArray peerId, jstring protocol)
{
    unsigned char *nativeKey = getNativeKey(env, peerId);
    const char *nativeProto = (*env)->GetStringUTFChars(env, protocol, NULL);
    osdg_result_t res = osdg_connect_to_remote((osdg_connection_t)grid, (osdg_connection_t)peer, nativeKey, nativeProto);

    (*env)->ReleaseByteArrayElements(env, peerId, nativeKey, 0);
    (*env)->ReleaseStringUTFChars(env, protocol, nativeProto);
    return res;
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_pair_1remote(JNIEnv *env, jclass cl, jlong grid, jlong peer, jstring otp)
{
    const char *nativeOtp = (*env)->GetStringUTFChars(env, otp, NULL);
    osdg_result_t res = osdg_pair_remote((osdg_connection_t)grid, (osdg_connection_t)peer, nativeOtp);

    (*env)->ReleaseStringUTFChars(env, otp, nativeOtp);
    return res;
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_connection_1close(JNIEnv *env, jclass cl, jlong conn)
{
    return osdg_connection_close((osdg_connection_t)conn);
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_send_1data(JNIEnv *env, jclass cl, jlong conn, jbyteArray data)
{
    jbyte *nativeData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize size = (*env)->GetArrayLength(env, data);
    osdg_result_t res = osdg_send_data((osdg_connection_t)conn, nativeData, size);

    (*env)->ReleaseByteArrayElements(env, data, nativeData, 0);
    return res;
}

JNIEXPORT void JNICALL Java_org_opensdg_OpenSDG_set_1blocking_1mode(JNIEnv *env, jclass cl, jlong conn, jboolean blocking)
{
    osdg_set_blocking_mode((osdg_connection_t)conn, blocking);
}

JNIEXPORT jboolean JNICALL Java_org_opensdg_OpenSDG_get_1blocking_1mode(JNIEnv *env, jclass cl, jlong conn)
{
    return osdg_get_blocking_mode((osdg_connection_t)conn);
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_get_1connection_1state(JNIEnv *env, jclass cl, jlong conn)
{
    return osdg_get_connection_state((osdg_connection_t)conn);
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_get_1last_1result(JNIEnv * env, jclass cl, jlong conn)
{
    return osdg_get_last_result((osdg_connection_t)conn);
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_get_1last_1errno(JNIEnv *env, jclass cl, jlong conn)
{
    return osdg_get_last_errno((osdg_connection_t)conn);
}

JNIEXPORT jbyteArray JNICALL Java_org_opensdg_OpenSDG_get_1peer_1id(JNIEnv *env, jclass cl, jlong conn)
{
    return makeJavaKey(env, osdg_get_peer_id((osdg_connection_t)conn));
}

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_set_1ping_1interval(JNIEnv *env, jclass cl, jlong conn, jint seconds)
{
    return osdg_set_ping_interval((osdg_connection_t)conn, seconds);
}
