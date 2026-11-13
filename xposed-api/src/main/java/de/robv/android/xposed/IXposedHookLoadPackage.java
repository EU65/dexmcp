package de.robv.android.xposed;

/**
 * Compile-time stub of the classic Xposed API (api-82). The real classes are provided
 * by LSPosed at runtime; this module is only used with `compileOnly`.
 */
public interface IXposedHookLoadPackage {
    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;
}
