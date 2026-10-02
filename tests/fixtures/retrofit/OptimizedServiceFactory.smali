.class public final Lorg/wikipedia/dataclient/ServiceFactory;
.super Ljava/lang/Object;
.source "r8-map-id-321e9a7750237ca8828ff95ce576299e4eed3a6d36bd60e4b44b8ad42b5a8a7c"







































































































.method public static createRetrofit$default(Lorg/wikipedia/dataclient/ServiceFactory;Lorg/wikipedia/dataclient/WikiSite;Ljava/lang/String;)Lretrofit2/Retrofit;
    .locals 7

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object p0, Lorg/wikipedia/dataclient/okhttp/OkHttpConnectionFactory;->client:Lokhttp3/OkHttpClient;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    new-instance v0, Lokhttp3/OkHttpClient$Builder;

    .line 10
    .line 11
    invoke-direct {v0}, Lokhttp3/OkHttpClient$Builder;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v1, p0, Lokhttp3/OkHttpClient;->dispatcher:Lokhttp3/Dispatcher;

    .line 15
    .line 16
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->dispatcher:Lokhttp3/Dispatcher;

    .line 17
    .line 18
    iget-object v1, p0, Lokhttp3/OkHttpClient;->connectionPool:Lokhttp3/ConnectionPool;

    .line 19
    .line 20
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->connectionPool:Lokhttp3/ConnectionPool;

    .line 21
    .line 22
    iget-object v1, p0, Lokhttp3/OkHttpClient;->interceptors:Ljava/util/List;

    .line 23
    .line 24
    iget-object v2, v0, Lokhttp3/OkHttpClient$Builder;->interceptors:Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-static {v2, v1}, Lkotlin/collections/CollectionsKt__MutableCollectionsKt;->addAll(Ljava/util/Collection;Ljava/lang/Iterable;)V

    .line 27
    .line 28
    .line 29
    iget-object v1, v0, Lokhttp3/OkHttpClient$Builder;->networkInterceptors:Ljava/util/ArrayList;

    .line 30
    .line 31
    iget-object v3, p0, Lokhttp3/OkHttpClient;->networkInterceptors:Ljava/util/List;

    .line 32
    .line 33
    invoke-static {v1, v3}, Lkotlin/collections/CollectionsKt__MutableCollectionsKt;->addAll(Ljava/util/Collection;Ljava/lang/Iterable;)V

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lokhttp3/OkHttpClient;->eventListenerFactory:Lokhttp3/internal/_UtilJvmKt$$ExternalSyntheticLambda0;

    .line 37
    .line 38
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->eventListenerFactory:Lokhttp3/internal/_UtilJvmKt$$ExternalSyntheticLambda0;

    .line 39
    .line 40
    iget-boolean v1, p0, Lokhttp3/OkHttpClient;->retryOnConnectionFailure:Z

    .line 41
    .line 42
    iput-boolean v1, v0, Lokhttp3/OkHttpClient$Builder;->retryOnConnectionFailure:Z

    .line 43
    .line 44
    iget-boolean v1, p0, Lokhttp3/OkHttpClient;->fastFallback:Z

    .line 45
    .line 46
    iput-boolean v1, v0, Lokhttp3/OkHttpClient$Builder;->fastFallback:Z

    .line 47
    .line 48
    iget-object v1, p0, Lokhttp3/OkHttpClient;->authenticator:Lokhttp3/Protocol$Companion;

    .line 49
    .line 50
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->authenticator:Lokhttp3/Protocol$Companion;

    .line 51
    .line 52
    iget-boolean v1, p0, Lokhttp3/OkHttpClient;->followRedirects:Z

    .line 53
    .line 54
    iput-boolean v1, v0, Lokhttp3/OkHttpClient$Builder;->followRedirects:Z

    .line 55
    .line 56
    iget-boolean v1, p0, Lokhttp3/OkHttpClient;->followSslRedirects:Z

    .line 57
    .line 58
    iput-boolean v1, v0, Lokhttp3/OkHttpClient$Builder;->followSslRedirects:Z

    .line 59
    .line 60
    iget-object v1, p0, Lokhttp3/OkHttpClient;->cookieJar:Lokhttp3/CookieJar;

    .line 61
    .line 62
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->cookieJar:Lokhttp3/CookieJar;

    .line 63
    .line 64
    iget-object v1, p0, Lokhttp3/OkHttpClient;->cache:Lokhttp3/Cache;

    .line 65
    .line 66
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->cache:Lokhttp3/Cache;

    .line 67
    .line 68
    iget-object v1, p0, Lokhttp3/OkHttpClient;->dns:Lokhttp3/Dns$Companion$SYSTEM$1;

    .line 69
    .line 70
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->dns:Lokhttp3/Dns$Companion$SYSTEM$1;

    .line 71
    .line 72
    iget-object v1, p0, Lokhttp3/OkHttpClient;->proxySelector:Ljava/net/ProxySelector;

    .line 73
    .line 74
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->proxySelector:Ljava/net/ProxySelector;

    .line 75
    .line 76
    iget-object v1, p0, Lokhttp3/OkHttpClient;->proxyAuthenticator:Lokhttp3/Protocol$Companion;

    .line 77
    .line 78
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->proxyAuthenticator:Lokhttp3/Protocol$Companion;

    .line 79
    .line 80
    iget-object v1, p0, Lokhttp3/OkHttpClient;->socketFactory:Ljavax/net/SocketFactory;

    .line 81
    .line 82
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->socketFactory:Ljavax/net/SocketFactory;

    .line 83
    .line 84
    iget-object v1, p0, Lokhttp3/OkHttpClient;->sslSocketFactoryOrNull:Ljavax/net/ssl/SSLSocketFactory;

    .line 85
    .line 86
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->sslSocketFactoryOrNull:Ljavax/net/ssl/SSLSocketFactory;

    .line 87
    .line 88
    iget-object v1, p0, Lokhttp3/OkHttpClient;->x509TrustManager:Ljavax/net/ssl/X509TrustManager;

    .line 89
    .line 90
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->x509TrustManagerOrNull:Ljavax/net/ssl/X509TrustManager;

    .line 91
    .line 92
    iget-object v1, p0, Lokhttp3/OkHttpClient;->connectionSpecs:Ljava/util/List;

    .line 93
    .line 94
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->connectionSpecs:Ljava/util/List;

    .line 95
    .line 96
    iget-object v1, p0, Lokhttp3/OkHttpClient;->protocols:Ljava/util/List;

    .line 97
    .line 98
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->protocols:Ljava/util/List;

    .line 99
    .line 100
    iget-object v1, p0, Lokhttp3/OkHttpClient;->hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 101
    .line 102
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 103
    .line 104
    iget-object v1, p0, Lokhttp3/OkHttpClient;->certificatePinner:Lokhttp3/CertificatePinner;

    .line 105
    .line 106
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->certificatePinner:Lokhttp3/CertificatePinner;

    .line 107
    .line 108
    iget-object v1, p0, Lokhttp3/OkHttpClient;->certificateChainCleaner:Landroidx/work/ListenableFutureKt;

    .line 109
    .line 110
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->certificateChainCleaner:Landroidx/work/ListenableFutureKt;

    .line 111
    .line 112
    iget-short v1, p0, Lokhttp3/OkHttpClient;->connectTimeoutMillis:S

    .line 113
    .line 114
    iput-short v1, v0, Lokhttp3/OkHttpClient$Builder;->connectTimeout:S

    .line 115
    .line 116
    iget v1, p0, Lokhttp3/OkHttpClient;->readTimeoutMillis:I

    .line 117
    .line 118
    iput v1, v0, Lokhttp3/OkHttpClient$Builder;->readTimeout:I

    .line 119
    .line 120
    iget-short v1, p0, Lokhttp3/OkHttpClient;->writeTimeoutMillis:S

    .line 121
    .line 122
    iput-short v1, v0, Lokhttp3/OkHttpClient$Builder;->writeTimeout:S

    .line 123
    .line 124
    iget-char v1, p0, Lokhttp3/OkHttpClient;->webSocketCloseTimeout:C

    .line 125
    .line 126
    iput-char v1, v0, Lokhttp3/OkHttpClient$Builder;->webSocketCloseTimeout:C

    .line 127
    .line 128
    iget-short v1, p0, Lokhttp3/OkHttpClient;->minWebSocketMessageToCompress:S

    .line 129
    .line 130
    int-to-long v3, v1

    .line 131
    long-to-int v1, v3

    .line 132
    iput-short v1, v0, Lokhttp3/OkHttpClient$Builder;->minWebSocketMessageToCompress:S

    .line 133
    .line 134
    iget-object v1, p0, Lokhttp3/OkHttpClient;->routeDatabase:Lokhttp3/ConnectionPool;

    .line 135
    .line 136
    iput-object v1, v0, Lokhttp3/OkHttpClient$Builder;->routeDatabase:Lokhttp3/ConnectionPool;

    .line 137
    .line 138
    iget-object p0, p0, Lokhttp3/OkHttpClient;->taskRunner:Lokhttp3/internal/concurrent/TaskRunner;

    .line 139
    .line 140
    iput-object p0, v0, Lokhttp3/OkHttpClient$Builder;->taskRunner:Lokhttp3/internal/concurrent/TaskRunner;

    .line 141
    .line 142
    invoke-virtual {v0}, Lokhttp3/OkHttpClient$Builder;->readTimeout()V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    const/4 v1, 0x0

    .line 150
    move v3, v1

    .line 151
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 152
    .line 153
    .line 154
    move-result v4

    .line 155
    if-eqz v4, :cond_1

    .line 156
    .line 157
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    check-cast v4, Lokhttp3/Interceptor;

    .line 162
    .line 163
    instance-of v4, v4, Lokhttp3/logging/HttpLoggingInterceptor;

    .line 164
    .line 165
    if-eqz v4, :cond_0

    .line 166
    .line 167
    goto :goto_1

    .line 168
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 169
    .line 170
    goto :goto_0

    .line 171
    :cond_1
    const/4 v3, -0x1

    .line 172
    :goto_1
    new-instance p0, Lorg/wikipedia/dataclient/ServiceFactory$LanguageVariantHeaderInterceptor;

    .line 173
    .line 174
    invoke-direct {p0, p1}, Lorg/wikipedia/dataclient/ServiceFactory$LanguageVariantHeaderInterceptor;-><init>(Lorg/wikipedia/dataclient/WikiSite;)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v2, v3, p0}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    new-instance p0, Ljava/util/ArrayList;

    .line 181
    .line 182
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 183
    .line 184
    .line 185
    new-instance p1, Ljava/util/ArrayList;

    .line 186
    .line 187
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 188
    .line 189
    .line 190
    new-instance v2, Lokhttp3/HttpUrl$Builder;

    .line 191
    .line 192
    invoke-direct {v2, v1}, Lokhttp3/HttpUrl$Builder;-><init>(B)V

    .line 193
    .line 194
    .line 195
    const/4 v3, 0x0

    .line 196
    invoke-virtual {v2, v3, p2}, Lokhttp3/HttpUrl$Builder;->parse$okhttp(Lokhttp3/HttpUrl;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v2}, Lokhttp3/HttpUrl$Builder;->build()Lokhttp3/HttpUrl;

    .line 200
    .line 201
    .line 202
    move-result-object p2

    .line 203
    iget-object v2, p2, Lokhttp3/HttpUrl;->pathSegments:Ljava/util/ArrayList;

    .line 204
    .line 205
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 206
    .line 207
    .line 208
    move-result v4

    .line 209
    add-int/lit8 v4, v4, -0x1

    .line 210
    .line 211
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    const-string v4, ""

    .line 216
    .line 217
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v2

    .line 221
    if-eqz v2, :cond_2

    .line 222
    .line 223
    new-instance v2, Lokhttp3/OkHttpClient;

    .line 224
    .line 225
    invoke-direct {v2, v0}, Lokhttp3/OkHttpClient;-><init>(Lokhttp3/OkHttpClient$Builder;)V

    .line 226
    .line 227
    .line 228
    sget-object v0, Lorg/wikipedia/json/JsonUtil;->json:Lkotlinx/serialization/json/JsonImpl;

    .line 229
    .line 230
    sget-object v3, Lokhttp3/MediaType;->TYPE_SUBTYPE:Lkotlin/text/Regex;

    .line 231
    .line 232
    const-string v3, "application/json"

    .line 233
    .line 234
    invoke-static {v3}, Lokhttp3/MediaType$Companion;->get(Ljava/lang/String;)Lokhttp3/MediaType;

    .line 235
    .line 236
    .line 237
    move-result-object v3

    .line 238
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 239
    .line 240
    .line 241
    new-instance v4, Lretrofit2/converter/kotlinx/serialization/Factory;

    .line 242
    .line 243
    new-instance v5, Lorg/wikipedia/page/PageFragment$AvCallback;

    .line 244
    .line 245
    const/16 v6, 0xe

    .line 246
    .line 247
    invoke-direct {v5, v0, v6}, Lorg/wikipedia/page/PageFragment$AvCallback;-><init>(Ljava/lang/Object;B)V

    .line 248
    .line 249
    .line 250
    invoke-direct {v4, v3, v5}, Lretrofit2/converter/kotlinx/serialization/Factory;-><init>(Lokhttp3/MediaType;Lorg/wikipedia/page/PageFragment$AvCallback;)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    sget-object v0, Lretrofit2/Platform;->callbackExecutor:Lretrofit2/AndroidMainExecutor;

    .line 257
    .line 258
    sget-object v3, Lretrofit2/Platform;->builtInFactories:Lretrofit2/Reflection;

    .line 259
    .line 260
    new-instance v4, Ljava/util/ArrayList;

    .line 261
    .line 262
    invoke-direct {v4, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v3, v0}, Lretrofit2/Reflection;->createDefaultCallAdapterFactories(Ljava/util/concurrent/Executor;)Ljava/util/List;

    .line 266
    .line 267
    .line 268
    move-result-object p1

    .line 269
    invoke-virtual {v4, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 270
    .line 271
    .line 272
    invoke-virtual {v3}, Lretrofit2/Reflection;->createDefaultConverterFactories()Ljava/util/List;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 277
    .line 278
    .line 279
    move-result v3

    .line 280
    new-instance v5, Ljava/util/ArrayList;

    .line 281
    .line 282
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 283
    .line 284
    .line 285
    move-result v6

    .line 286
    add-int/lit8 v6, v6, 0x1

    .line 287
    .line 288
    add-int/2addr v6, v3

    .line 289
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 290
    .line 291
    .line 292
    new-instance v3, Lretrofit2/BuiltInConverters;

    .line 293
    .line 294
    invoke-direct {v3, v1}, Lretrofit2/BuiltInConverters;-><init>(B)V

    .line 295
    .line 296
    .line 297
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 298
    .line 299
    .line 300
    invoke-virtual {v5, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 301
    .line 302
    .line 303
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 304
    .line 305
    .line 306
    new-instance p0, Lretrofit2/Retrofit;

    .line 307
    .line 308
    invoke-static {v5}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    invoke-static {v4}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 317
    .line 318
    .line 319
    invoke-direct {p0, v2, p2, v0, v1}, Lretrofit2/Retrofit;-><init>(Lokhttp3/OkHttpClient;Lokhttp3/HttpUrl;Ljava/util/List;Ljava/util/List;)V

    .line 320
    .line 321
    .line 322
    return-object p0

    .line 323
    :cond_2
    const-string p0, "baseUrl must end in /: "

    .line 324
    .line 325
    invoke-static {p0, p2}, Lcom/google/firebase/messaging/FirebaseMessaging$AutoInit$$ExternalSyntheticLambda0;->m(Ljava/lang/String;Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    return-object v3
.end method

.method public static get(Lorg/wikipedia/dataclient/WikiSite;)Lorg/wikipedia/dataclient/Service;
    .locals 1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    sget-object v0, Lorg/wikipedia/dataclient/ServiceFactory;->SERVICE_CACHE:Landroidx/appcompat/widget/ResourceManagerInternal$ColorFilterLruCache;

    invoke-virtual {v0, p0}, Landroidx/collection/LruCache;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast p0, Lorg/wikipedia/dataclient/Service;

    return-object p0
.end method






















































































































































































































































































































.method public final get(Lorg/wikipedia/dataclient/WikiSite;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p1}, Lorg/wikipedia/dataclient/WikiSite;->url()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    const-string v0, "/"

    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    :cond_0
    invoke-static {p0, p1, p2}, Lorg/wikipedia/dataclient/ServiceFactory;->createRetrofit$default(Lorg/wikipedia/dataclient/ServiceFactory;Lorg/wikipedia/dataclient/WikiSite;Ljava/lang/String;)Lretrofit2/Retrofit;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0, p3}, Lretrofit2/Retrofit;->create(Ljava/lang/Class;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method
