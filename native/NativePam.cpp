#include <string.h>
#include <iostream>
#include "com_blueprintit_security_pam_Pam.h"
#include "pamcalls.cpp"

using namespace std;

struct native_data
{
	jobject Pam;
	JNIEnv *env;
	jobject callback;
	pam_handle_t *pamhandle;
};

int handlecount=0;

struct native_data *create_data(JNIEnv *env, jobject obj)
{
	cout << "Allocating data\n";
	cout.flush();

	struct native_data *data = new (struct native_data);
	data->pamhandle=NULL;

	data->env=env;
	data->Pam=env->NewGlobalRef(obj);

	jmethodID methSetData = env->GetMethodID(env->GetObjectClass(obj),"setNativeData","([B)V");
	jbyteArray jaryData = env->NewByteArray(sizeof data);
	jbyte *pinned = env->GetByteArrayElements(jaryData,NULL);

	*((struct native_data**)pinned)=data;

	env->ReleaseByteArrayElements(jaryData,pinned,0);

	env->CallVoidMethod(obj,methSetData,jaryData);

	if (handlecount==0)
		open_pam();

	handlecount++;

	return data;
}

struct native_data *get_data(JNIEnv *env, jobject obj)
{
	jmethodID methGetData = env->GetMethodID(env->GetObjectClass(obj),"getNativeData","()[B");
	jbyteArray jaryData = (jbyteArray)env->CallObjectMethod(obj,methGetData);
	jbyte *pinned = env->GetByteArrayElements(jaryData,NULL);

	struct native_data *data = *((struct native_data**)pinned);

	env->ReleaseByteArrayElements(jaryData,pinned,0);

	return data;
}

void release_data(struct native_data *data)
{
	cout << "Releasing data\n";
	cout.flush();

	jmethodID methSetData = data->env->GetMethodID(data->env->GetObjectClass(data->Pam),"setNativeData","([B)V");
	data->env->CallVoidMethod(data->Pam,methSetData,NULL);

	data->env->DeleteGlobalRef(data->Pam);
	data->Pam=NULL;
	data->env=NULL;

	delete data;

	handlecount--;

	if (handlecount==0)
		close_pam();
}

static int pam_converser(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	struct native_data *data = (struct native_data*)appdata_ptr;
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
		const char *string = env->GetStringUTFChars(jstrResp,NULL);
		resps[i].resp = strdup(string);
		env->ReleaseStringUTFChars(jstrResp,string);
	}

	*resp = resps;

	return PAM_SUCCESS;
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_start
 * Signature: (Ljava/lang/String;Ljava/lang/String;Lcom/blueprintit/security/pam/PamCallback;)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1start
  (JNIEnv *env, jobject obj, jstring service, jstring user, jobject callback)
{
	struct native_data *data = create_data(env,obj);

	const char *pam_serv = env->GetStringUTFChars(service,NULL);
	const char *pam_user = env->GetStringUTFChars(user,NULL);

	pam_handle_t *handle;
	data->callback = env->NewGlobalRef(callback);

	struct pam_conv *conv = new struct pam_conv;
	conv->conv=&pam_converser;
	conv->appdata_ptr=(void*)data;

	int status = call_pam_start(strdup(pam_serv),strdup(pam_user),conv,&handle);
	if (status==PAM_SUCCESS)
	{
		data->pamhandle=handle;
	}
	else
	{
		release_data(data);
	}

	env->ReleaseStringUTFChars(service,pam_serv);
	env->ReleaseStringUTFChars(user,pam_user);

	return status;
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_end
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1end
  (JNIEnv *env, jobject obj, jint pam_status)
{
	cout << "Proper call to pam_end\n";
	cout.flush();
	struct native_data *data = get_data(env,obj);
	int status = call_pam_end(data->pamhandle,pam_status);
	data->pamhandle=NULL;
	release_data(data);
	return status;
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_authenticate
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1authenticate
  (JNIEnv *env, jobject obj, jint flags)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	return call_pam_authenticate(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_setcred
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1setcred
  (JNIEnv *env, jobject obj, jint flags)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	return call_pam_setcred(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_acct_mgmt
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1acct_1mgmt
  (JNIEnv *env, jobject obj, jint flags)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	return call_pam_acct_mgmt(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_open_session
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1open_1session
  (JNIEnv *env, jobject obj, jint flags)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	return call_pam_open_session(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_close_session
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1close_1session
  (JNIEnv *env, jobject obj, jint flags)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	return call_pam_close_session(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_chauthtok
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1chauthtok
  (JNIEnv *env, jobject obj, jint flags)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	return call_pam_chauthtok(handle,flags);
}

/*
 * Class:     com_blueprintit_security_pam_Pam
 * Method:    call_pam_strerror
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_blueprintit_security_pam_Pam_call_1pam_1strerror
  (JNIEnv *env, jobject obj, jint errnum)
{
	struct native_data *data = get_data(env,obj);
	pam_handle_t *handle = data->pamhandle;
	const char *error = call_pam_strerror(handle,errnum);
	return env->NewStringUTF(error);
}
