#include <string.h>
#include <map>
#include "com_blueprintit_security_pam_Pam.h"
#include "pamcalls.cpp"

using namespace std;

map<int, pam_handle_t*> handles;

extern "C" jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
	open_pam();
	return JNI_VERSION_1_4;
}

extern "C" void JNI_OnUnload(JavaVM *vm, void *reserved)
{
	close_pam();
}

pam_handle_t* fetch_handle(int id)
{
	pam_handle_t* handle = handles[id];
	return handle;
}

void set_handle(int id, pam_handle_t *handle)
{
	handles.insert(make_pair(id,handle));
}

void clear_handle(int id)
{
	handles.erase(id);
}

struct pam_data
{
	jobject callback;
	JNIEnv *env;
};

static int pam_converser(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	struct pam_data *data = (struct pam_data*)appdata_ptr;
	JNIEnv *env = data->env;

	jclass clsPamMessage = env->FindClass("com/blueprintit/security/pam/PamMessage");
	jmethodID methPMinit = env->GetMethodID(clsPamMessage,"<init>","(ILjava/lang/String;)V");

	jobjectArray jaryMessage = env->NewObjectArray(num_msg,clsPamMessage,NULL);

	for (int i=0; i<num_msg; i++)
	{
		jobject objMessage = env->NewObject(clsPamMessage,methPMinit,(jint)msg[i]->msg_style,env->NewStringUTF(msg[i]->msg));
		env->SetObjectArrayElement(jaryMessage,i,objMessage);
	}

	jclass clsCallback = env->GetObjectClass(data->callback);
	jmethodID methCallback = env->GetMethodID(clsCallback,"callback","([Lcom/blueprintit/security/pam/PamMessage;)[Lcom/blueprintit/security/pam/PamResponse;");
	jobjectArray jaryResponse = (jobjectArray)env->CallObjectMethod(data->callback,methCallback,jaryMessage);
	
	jclass clsPamResponse = env->FindClass("com/blueprintit/security/pam/PamResponse");
	jmethodID methGetResponse = env->GetMethodID(clsPamResponse,"getResponse","()Ljava/lang/String;");
	jmethodID methGetResponseCode = env->GetMethodID(clsPamResponse,"getResponseCode","()I");

	int length = env->GetArrayLength(jaryResponse);
	
	*resp = NULL;

	if (length!=num_msg)
		return PAM_CONV_ERR;

	struct pam_response *resps = new (struct pam_response)[length];

	for (int i=0; i<length; i++)
	{
		jobject objResponse = env->GetObjectArrayElement(jaryResponse,i);
		resps[i].resp_retcode = env->CallIntMethod(objResponse,methGetResponseCode);
		jstring jstrResp = (jstring)env->CallObjectMethod(objResponse,methGetResponse);
		const char *string = env->GetStringUTFChars(jstrResp,0);
		resps[i].resp = strdup(string);
		env->ReleaseStringUTFChars(jstrResp,string);
	}

	*resp = resps;

	return PAM_SUCCESS;
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_start
 * Signature: (Ljava/lang/String;Ljava/lang/String;Lcom/blueprintit/security/pam/PamCallback;I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1start
  (JNIEnv *env, jobject obj, jstring service, jstring user, jobject callback, jint id)
{
	const char *pam_serv = env->GetStringUTFChars(service,0);
	const char *pam_user = env->GetStringUTFChars(user,0);

	pam_handle_t *handle;
	jobject globalref = env->NewGlobalRef(callback);

	struct pam_data *data = new struct pam_data;
	data->callback=globalref;
	data->env=env;

	struct pam_conv *conv = new struct pam_conv;
	conv->conv=&pam_converser;
	conv->appdata_ptr=(void*)data;

	int status = call_pam_start(strdup(pam_serv),strdup(pam_user),conv,&handle);
	if (status==PAM_SUCCESS)
	{
		set_handle(id,handle);
	}

	env->ReleaseStringUTFChars(service,pam_serv);
	env->ReleaseStringUTFChars(user,pam_user);

	return status;
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_end
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1end
  (JNIEnv *env, jobject obj, jint id, jint pam_status)
{
	pam_handle_t *handle = fetch_handle(id);
	int status = call_pam_end(handle,pam_status);
	clear_handle(id);
	return status;
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_authenticate
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1authenticate
  (JNIEnv *env, jobject obj, jint id, jint flags)
{
	pam_handle_t *handle = fetch_handle(id);
	return call_pam_authenticate(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_setcred
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1setcred
  (JNIEnv *env, jobject obj, jint id, jint flags)
{
	pam_handle_t *handle = fetch_handle(id);
	return call_pam_setcred(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_acct_mgmt
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1acct_1mgmt
  (JNIEnv *env, jobject obj, jint id, jint flags)
{
	pam_handle_t *handle = fetch_handle(id);
	return call_pam_acct_mgmt(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_open_session
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1open_1session
  (JNIEnv *env, jobject obj, jint id, jint flags)
{
	pam_handle_t *handle = fetch_handle(id);
	return call_pam_open_session(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_close_session
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1close_1session
  (JNIEnv *env, jobject obj, jint id, jint flags)
{
	pam_handle_t *handle = fetch_handle(id);
	return call_pam_close_session(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_chauthtok
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1chauthtok
  (JNIEnv *env, jobject obj, jint id, jint flags)
{
	pam_handle_t *handle = fetch_handle(id);
	return call_pam_chauthtok(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_strerror
 * Signature: (II)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1strerror
  (JNIEnv *env, jobject obj, jint id, jint errnum)
{
	pam_handle_t *handle = fetch_handle(id);
	const char *error = call_pam_strerror(handle,errnum);
	return env->NewStringUTF(error);
}
