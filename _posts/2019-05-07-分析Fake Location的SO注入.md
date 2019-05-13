---
layout:     post                    # 使用的布局（不需要改）
title:      分析Fake Location的SO注入      # 标题 
subtitle:   安卓逆向 SO注入 #副标题
date:       2019-05-07              # 时间
author:     BC                      # 作者
header-img: img/post-bg-fake.png    #这篇文章标题背景图片
catalog: true                       # 是否归档
tags:                               #标签
    - 安卓逆向
---

## 前言
    笔者最近玩一个山寨pokemongo的手游 使用了Fake Location作为模拟定位软件，对其中反检测功能的实现原理颇为感兴趣
    想知道他是怎么绕过ptrace保护注入进程 实现hook功能的
    这项技术的意义在于可以加固保护有hook功能的程序 而xposed插件就是近乎裸奔
    

## 分析SuperSU日志
![SuperSU日志](img/post-fake-supersu.png)
  
inject -P zygote -l initzygote.so -n fakelocation  
可以看出是zygote注入，zygote注入可以解决目标进程被ptrace保护的问题  
linux的zygote机制此处略  
向zygote进程中注入initzygote.so文件，fakelocation包名作为白名单不注入。


## 分析initzygote.so

```c
int init(void)
{
  int v0; // r0
  JNIEnv *v1; // r4
  int v2; // r0
  bool v3; // zf
  int v4; // ST24_4
  int v5; // ST10_4
  int v6; // r5
  int v7; // r9
  int v8; // ST18_4
  int v9; // r8
  int v10; // r0
  int v11; // ST1C_4
  int v12; // r6
  int v13; // r6
  int v14; // ST14_4
  int v15; // r8
  int v16; // r5
  int v17; // ST0C_4
  int result; // r0
  signed int v19; // r0
  const char *v20; // r2
  char s; // [sp+28h] [bp-220h]
  int v22; // [sp+228h] [bp-20h]

  v0 = _android_log_print(4, "LINJECT.native", "InitApp is Executing!!");
  v1 = (JNIEnv *)j_getJniEnv(v0);
  if ( !v1 )
  {
    result = _stack_chk_guard - v22;
    if ( _stack_chk_guard != v22 )
      return result;
    v19 = 4;
    v20 = "jni_env is NULL!!";
    goto LABEL_11;
  }
  v2 = j_isSignQualified();
  v3 = v2 == -2;
  if ( v2 != -2 )
    v3 = v2 == 0;
  if ( v3 )
  {
    __android_log_print(4, "LINJECT.native", "jni_env is %p", v1);
    v4 = ((int (__fastcall *)(JNIEnv *, const char *))(*v1)->NewStringUTF)(v1, "/data/fakeloc/zygote_dex");
    v5 = ((int (__fastcall *)(JNIEnv *, char *))(*v1)->NewStringUTF)(v1, apkpath[0]);
    v6 = ((int (__fastcall *)(JNIEnv *, const char *))(*v1)->FindClass)(v1, "dalvik/system/DexClassLoader");
    snprintf(
      &s,
      0x200u,
      "(%s%s%s%s)V",
      "Ljava/lang/String;",
      "Ljava/lang/String;",
      "Ljava/lang/String;",
      "Ljava/lang/ClassLoader;");
    v7 = ((int (__fastcall *)(JNIEnv *, int, const char *, char *))(*v1)->GetMethodID)(v1, v6, "<init>", &s);
    snprintf(&s, 0x200u, "(%s)%s", "Ljava/lang/String;", "Ljava/lang/Class;");
    v8 = v6;
    v9 = ((int (__fastcall *)(JNIEnv *, int, const char *, char *))(*v1)->GetMethodID)(v1, v6, "loadClass", &s);
    v10 = j_getSystemClassLoader(v1);
    v11 = v10;
    v12 = v10;
    __android_log_print(4, "LINJECT.native", "Oat2dex...");
    v13 = _JNIEnv::NewObject(v1, v6, v7, v5, v4, 0, v12);
    __android_log_print(4, "LINJECT.native", "Oat2dex OK.");
    v14 = ((int (__fastcall *)(JNIEnv *, const char *))(*v1)->NewStringUTF)(
            v1,
            "com.lerist.inject.fakelocation.InjectDex");
    v15 = _JNIEnv::CallObjectMethod(v1, v13, v9, v14);
    __android_log_print(4, "LINJECT.native", "entry_class:%p", v15);
    v16 = ((int (__fastcall *)(JNIEnv *, int, const char *, const char *))(*v1)->GetStaticMethodID)(
            v1,
            v15,
            "initZygote",
            "(Ljava/lang/Object;)[Ljava/lang/Object;");
    __android_log_print(4, "LINJECT.native", "Invoke method...");
    v17 = _JNIEnv::CallStaticObjectMethod(v1, v15, v16, 0);
    __android_log_print(4, "LINJECT.native", "InitApp is finished");
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v4);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v5);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v4);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v8);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v11);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v13);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v14);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v15);
    ((void (__fastcall *)(JNIEnv *, int))(*v1)->DeleteLocalRef)(v1, v17);
    return _stack_chk_guard - v22;
  }
  result = _stack_chk_guard - v22;
  if ( _stack_chk_guard == v22 )
  {
    v19 = 6;
    v20 = "Illegal application!";
LABEL_11:
    result = j___android_log_print(v19, "LINJECT.native", v20);
  }
  return result;
}
```
main函数里 反射执行了com.lerist.inject.fakelocation.InjectDex.initZygote方法
```java
public static java.lang.Object[] initZygote(java.lang.Object r3) {
        r0 = new java.lang.StringBuilder;
        r0.<init>();
        r1 = "initZygote.";
        r0.append(r1);
        r0.append(r3);
        r3 = r0.toString();
        r0 = "InjectDex";
        android.util.Log.d(r0, r3);
        r3 = new java.lang.StringBuilder;
        r3.<init>();
        r1 = "";
        r3.append(r1);
        r1 = android.os.Build.CPU_ABI;
        r3.append(r1);
        r3 = r3.toString();
        r1 = "64";
        r3 = r3.contains(r1);
        if (r3 == 0) goto L_0x0034;
    L_0x0031:
        r3 = "/data/fakeloc/liblhooker64.so";
        goto L_0x0036;
    L_0x0034:
        r3 = "/data/fakeloc/liblhooker.so";
    L_0x0036:
        com.lerist.lib.lhooker.LHooker.a(r3);
        r3 = 0;
        a.a.c.a.a.hook(r3);
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "initZygote finish.";
        r1.append(r2);
        r2 = com.lerist.lib.lhooker.LHooker.a;
        r1.append(r2);
        r1 = r1.toString();
        android.util.Log.d(r0, r1);
        return r3;
    }

```
在这里System.load加载了liblhooker.so 为hook库  
com.lerist.lib.lhooker.LHooker类中有多个hook相关JNI方法
```java
    public static native java.lang.Object findMethodNative(java.lang.Class r1, java.lang.String r2, java.lang.String r3);

    public static native java.lang.Object[] getKeys(byte[] r1, java.lang.String r2);

    private static native boolean hookMethodNative(java.lang.Object r1, java.lang.reflect.Method r2, java.lang.reflect.Method r3, java.lang.reflect.Method r4);

    public static native int init(int r1);

    public static native void resumeAll(long r1);

    public static native long suspendAll();

```

## 小结
    1. Fake软件使用了非xposed的hook库
    2. 通过zygote注入hook用dex，在该dex里加载Hook用so
    3. 这样做的好处是可以绕过常见xposed检测，又可以对APP进行加固
    -1.笔者下一步选择使用whale框架+inlinehook，实现自己的hook工具

    

> to be continued
