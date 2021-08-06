package com.reactnativemsal;

import android.util.Pair;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.microsoft.identity.client.AcquireTokenParameters;
import com.microsoft.identity.client.AcquireTokenSilentParameters;
import com.microsoft.identity.client.AuthenticationCallback;
import com.microsoft.identity.client.IAccount;
import com.microsoft.identity.client.IAuthenticationResult;
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication;
import com.microsoft.identity.client.Prompt;
import com.microsoft.identity.client.PublicClientApplication;
import com.microsoft.identity.client.SilentAuthenticationCallback;
import com.microsoft.identity.client.exception.MsalException;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import java.io.ByteArrayInputStream;
import org.json.*;

public class RNMSALModule extends ReactContextBaseJavaModule {
    private IMultipleAccountPublicClientApplication publicClientApplication;

     private static JSONArray convertAuthoritiesToJson(ReadableArray readableArray) throws JSONException {
        boolean defaultbool = true;
        JSONArray array = new JSONArray();
        for (int i = 0; i < readableArray.size(); i++) {
            JSONObject object = new JSONObject();
            JSONObject audience = new JSONObject();
            audience.put("type", "AzureADMyOrg");
            audience.put("tenant_id", readableArray.getString(i).substring(readableArray.getString(i).lastIndexOf("/") + 1));
            object.put("type","AAD");
            object.put("audience", audience);
            object.put("default",defaultbool);
            if (defaultbool) {
                defaultbool = false;
            }
            array.put(object);
        }
        return array;
    }


    private static JSONArray convertArrayToJson(ReadableArray readableArray) throws JSONException {
        JSONArray array = new JSONArray();
        for (int i = 0; i < readableArray.size(); i++) {
            switch (readableArray.getType(i)) {
                case Null:
                    break;
                case Boolean:
                    array.put(readableArray.getBoolean(i));
                    break;
                case Number:
                    array.put(readableArray.getDouble(i));
                    break;
                case String:
                    array.put(readableArray.getString(i));
                    break;
                case Map:
                    array.put(convertMapToJson(readableArray.getMap(i)));
                    break;
                case Array:
                    array.put(convertArrayToJson(readableArray.getArray(i)));
                    break;
            }
        }
        return array;
    }

    private static JSONObject convertMapToJson(ReadableMap readableMap) throws JSONException {
        JSONObject object = new JSONObject();
        ReadableMapKeySetIterator iterator = readableMap.keySetIterator();
        while (iterator.hasNextKey()) {
            String key = iterator.nextKey();
            switch (key) {
                case "redirectUri":
                    object.put("redirect_uri", readableMap.getString(key));
                    break;
                case "clientId":
                    object.put("client_id", readableMap.getString(key));
                    break;
                case "knownAuthorities":
                    object.put("authorities", convertAuthoritiesToJson(readableMap.getArray(key)));
                    break;
            }
        }
        object.put("authorization_user_agent", "DEFAULT");
        object.put("broker_redirect_uri_registered", true);
        object.put("account_mode", "MULTIPLE");
        return object;
    }

    public RNMSALModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @NonNull
    @Override
    public String getName() {
        return "RNMSAL";
    }

    @ReactMethod
    public void createPublicClientApplication(ReadableMap params, Promise promise) {
        ReactApplicationContext context = getReactApplicationContext();
        try {
            JSONObject msalConfig = RNMSALModule.convertMapToJson(params.getMap("auth"));
            File file = File.createTempFile("RNMSAL_msal_config", ".tmp");
            file.deleteOnExit();

            System.out.println(msalConfig.toString());

            InputStream is = new ByteArrayInputStream(msalConfig.toString().getBytes("UTF-8"));
            FileUtils.copyInputStreamToFile(is, file);
            publicClientApplication =
                    PublicClientApplication.createMultipleAccountPublicClientApplication(
                            context, file);
            promise.resolve(null);
        } catch (Exception e) {
            promise.reject(e.toString());
        }
    }

    /*
    // Original version
    @ReactMethod
    public void createPublicClientApplication(ReadableMap params, Promise promise) {
        ReactApplicationContext context = getReactApplicationContext();
        try {
            InputStream inputStream = context.getAssets().open("msal_config.json");
            File file = File.createTempFile("RNMSAL_msal_config", ".tmp");
            file.deleteOnExit();
            FileUtils.copyInputStreamToFile(inputStream, file);
            publicClientApplication =
                    PublicClientApplication.createMultipleAccountPublicClientApplication(
                            context, file);
            promise.resolve(null);
        } catch (Exception e) {
            promise.reject(e);
        }
    }
    */

    @ReactMethod
    public void acquireToken(ReadableMap params, Promise promise) {
        try {
            AcquireTokenParameters.Builder acquireTokenParameters =
                    new AcquireTokenParameters.Builder()
                            .startAuthorizationFromActivity(this.getCurrentActivity());

            // Required parameters
            List<String> scopes = readableArrayToStringList(params.getArray("scopes"));
            acquireTokenParameters.withScopes(scopes);

            // Optional parameters
            if (params.hasKey("authority")) {
                acquireTokenParameters.fromAuthority(params.getString("authority"));
            }

            if (params.hasKey("promptType")) {
                acquireTokenParameters.withPrompt(Prompt.values()[params.getInt("promptType")]);
            }

            if (params.hasKey("loginHint")) {
                acquireTokenParameters.withLoginHint(params.getString("loginHint"));
            }

            if (params.hasKey("extraScopesToConsent")) {
                acquireTokenParameters.withOtherScopesToAuthorize(
                        readableArrayToStringList(params.getArray("extraScopesToConsent")));
            }

            if (params.hasKey("extraQueryParameters")) {
                List<Pair<String, String>> parameters = new ArrayList<>();
                for (Map.Entry<String, Object> entry :
                        params.getMap("extraQueryParameters").toHashMap().entrySet()) {
                    parameters.add(new Pair<>(entry.getKey(), entry.getValue().toString()));
                }
                acquireTokenParameters.withAuthorizationQueryStringParameters(parameters);
            }

            acquireTokenParameters.withCallback(getAuthInteractiveCallback(promise));
            publicClientApplication.acquireToken(acquireTokenParameters.build());
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    private AuthenticationCallback getAuthInteractiveCallback(Promise promise) {
        return new AuthenticationCallback() {
            @Override
            public void onCancel() {
                promise.reject("userCancel", "userCancel");
            }

            @Override
            public void onSuccess(IAuthenticationResult authenticationResult) {
                promise.resolve(msalResultToDictionary(authenticationResult));
            }

            @Override
            public void onError(MsalException exception) {
                promise.reject(exception);
            }
        };
    }

    @ReactMethod
    public void acquireTokenSilent(ReadableMap params, Promise promise) {
        try {
            AcquireTokenSilentParameters.Builder acquireTokenSilentParameters =
                    new AcquireTokenSilentParameters.Builder();

            // Required parameters
            List<String> scopes = readableArrayToStringList(params.getArray("scopes"));
            acquireTokenSilentParameters.withScopes(scopes);

            ReadableMap accountIn = params.getMap("account");
            String accountIdentifier = accountIn.getString("identifier");
            IAccount account = publicClientApplication.getAccount(accountIdentifier);
            acquireTokenSilentParameters.forAccount(account);

            // Optional parameters
            String authority =
                    publicClientApplication
                            .getConfiguration()
                            .getDefaultAuthority()
                            .getAuthorityURL()
                            .toString();
            if (params.hasKey("authority")) {
                authority = params.getString("authority");
            }
            acquireTokenSilentParameters.fromAuthority(authority);

            if (params.hasKey("forceRefresh")) {
                acquireTokenSilentParameters.forceRefresh(params.getBoolean("forceRefresh"));
            }

            acquireTokenSilentParameters.withCallback(getAuthSilentCallback(promise));
            publicClientApplication.acquireTokenSilentAsync(acquireTokenSilentParameters.build());
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    private SilentAuthenticationCallback getAuthSilentCallback(Promise promise) {
        return new SilentAuthenticationCallback() {
            @Override
            public void onSuccess(IAuthenticationResult authenticationResult) {
                promise.resolve(msalResultToDictionary(authenticationResult));
            }

            @Override
            public void onError(MsalException exception) {
                promise.reject(exception);
            }
        };
    }

    @ReactMethod
    public void getAccounts(Promise promise) {
        try {
            List<IAccount> accounts = publicClientApplication.getAccounts();
            WritableArray array = Arguments.createArray();
            for (IAccount account : accounts) {
                array.pushMap(accountToMap(account));
            }
            promise.resolve(array);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void getAccount(String accountIdentifier, Promise promise) {
        try {
            IAccount account = publicClientApplication.getAccount(accountIdentifier);
            promise.resolve(accountToMap(account));
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void removeAccount(ReadableMap accountIn, Promise promise) {
        try {
            // Required parameters
            String accountIdentifier = accountIn.getString(("identifier"));
            IAccount account = publicClientApplication.getAccount(accountIdentifier);

            publicClientApplication.removeAccount(
                    account,
                    new IMultipleAccountPublicClientApplication.RemoveAccountCallback() {
                        @Override
                        public void onRemoved() {
                            promise.resolve(true);
                        }

                        @Override
                        public void onError(@NonNull MsalException exception) {
                            promise.reject(exception);
                        }
                    });
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    private WritableMap msalResultToDictionary(IAuthenticationResult result) {
        WritableMap map = Arguments.createMap();
        map.putString("accessToken", result.getAccessToken());
        map.putString("expiresOn", String.format("%s", result.getExpiresOn().getTime() / 1000));
        map.putString("idToken", result.getAccount().getIdToken());
        map.putArray("scopes", Arguments.fromArray(result.getScope()));
        map.putString("tenantId", result.getTenantId());
        map.putMap("account", accountToMap(result.getAccount()));
        return map;
    }

    private WritableMap accountToMap(IAccount account) {
        WritableMap map = Arguments.createMap();
        map.putString("identifier", account.getId());
        map.putString("username", account.getUsername());
        map.putString("tenantId", account.getTenantId());
        Map<String, ?> claims = account.getClaims();
        if (claims != null) {
            map.putMap("claims", toWritableMap(claims));
        }
        return map;
    }

    private List<String> readableArrayToStringList(ReadableArray readableArray) {
        List<String> list = new ArrayList<>();
        for (Object item : readableArray.toArrayList()) {
            list.add(item.toString());
        }
        return list;
    }

    private WritableMap toWritableMap(Map<String, ?> map) {
        WritableMap writableMap = Arguments.createMap();
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value == null) {
                writableMap.putNull(key);
            } else if (value instanceof Boolean) {
                writableMap.putBoolean(key, (Boolean) value);
            } else if (value instanceof Double) {
                writableMap.putDouble(key, (Double) value);
            } else if (value instanceof Integer) {
                writableMap.putInt(key, (Integer) value);
            } else if (value instanceof String) {
                writableMap.putString(key, (String) value);
            } else if (value instanceof Map<?, ?>) {
                writableMap.putMap(key, toWritableMap((Map<String, ?>) value));
            } else if (value instanceof List<?>) {
                writableMap.putArray(key, toWritableArray((List<?>) value));
            }
        }
        return writableMap;
    }

    private WritableArray toWritableArray(List<?> list) {
        WritableArray writableArray = Arguments.createArray();
        for (Object value : list.toArray()) {
            if (value == null) {
                writableArray.pushNull();
            } else if (value instanceof Boolean) {
                writableArray.pushBoolean((Boolean) value);
            } else if (value instanceof Double) {
                writableArray.pushDouble((Double) value);
            } else if (value instanceof Integer) {
                writableArray.pushInt((Integer) value);
            } else if (value instanceof String) {
                writableArray.pushString((String) value);
            } else if (value instanceof Map<?, ?>) {
                writableArray.pushMap(toWritableMap((Map<String, ?>) value));
            } else if (value instanceof List<?>) {
                writableArray.pushArray(toWritableArray((List<?>) value));
            }
        }
        return writableArray;
    }
}
