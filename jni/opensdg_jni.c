#include "org_opensdg_OpenSDG.h"
#include "opensdg.h"

static JavaVM *jvm;
static JNIEnv *main_env;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    jvm = vm;
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

static void jni_attach(void)
{
    (*jvm)->AttachCurrentThread(jvm, (void **)&main_env, NULL);
}

static void jni_detach(void)
{
    (*jvm)->DetachCurrentThread(jvm);
}

static const struct osdg_main_loop_callbacks jni_mainloop_cb =
{
    jni_attach,
    jni_detach
};

JNIEXPORT jint JNICALL Java_org_opensdg_OpenSDG_init(JNIEnv *env, jclass cl)
{
    osdg_result_t res;
    
    osdg_set_mainloop_callbacks(&jni_mainloop_cb);
    res = osdg_init();
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

static jbyteArray makeJavaArray(JNIEnv *env, const void *data, unsigned int len)
{
    jbyteArray array = (*env)->NewByteArray(env, len);

    (*env)->SetByteArrayRegion(env, array, 0, len, data);
    return array;
}

static jbyteArray makeJavaKey(JNIEnv *env, const osdg_key_t nativeKey)
{
    return makeJavaArray(env, nativeKey, sizeof(osdg_key_t));
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

static void connection_state_change(osdg_connection_t conn, enum osdg_connection_state state)
{
    jobject obj = osdg_get_user_data(conn);
    jclass cl = (*main_env)->GetObjectClass(main_env, obj);
    jmethodID mid = (*main_env)->GetMethodID(main_env, cl, "osdg_status_change_cb", "(I)V");

    (*main_env)->CallVoidMethod(main_env, obj, mid, state);
}

static osdg_result_t connection_receive_data(osdg_connection_t conn, const void *data, unsigned int len)
{
    jobject obj = osdg_get_user_data(conn);
    jclass cl = (*main_env)->GetObjectClass(main_env, obj);
    jmethodID mid = (*main_env)->GetMethodID(main_env, cl, "osdg_data_receive_cb", "([B)I");
    jbyteArray jData = makeJavaArray(main_env, data, len);

    return (*main_env)->CallIntMethod(main_env, obj, mid, jData);
}

JNIEXPORT jlong JNICALL Java_org_opensdg_OpenSDG_connection_1create(JNIEnv *env, jclass cl, jobject jConn)
{
    osdg_connection_t conn = osdg_connection_create();

    if (conn)
    {
        osdg_set_user_data(conn, (void *)jConn);
        osdg_set_state_change_callback(conn, connection_state_change);
        osdg_set_receive_data_callback(conn, connection_receive_data);
    }

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
