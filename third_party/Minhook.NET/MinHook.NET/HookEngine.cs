using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    public sealed class HookEngine : IDisposable {

        MemoryAllocator memoryAllocator = new MemoryAllocator();
        Dictionary<Delegate, Hook> originalHookMapping = new Dictionary<Delegate, Hook>();
        Dictionary<Delegate, Hook> detourHookMapping = new Dictionary<Delegate, Hook>();
        // MODIFIED: 2026-08-04 支持原生 detour 地址 —— 按 target 地址跟踪原生 detour hook
        // (CreateHook(IntPtr, IntPtr) 重载创建; 无 delegate 参与, 仅 trampoline 生成 + patch)。
        Dictionary<IntPtr, Hook> nativeHookMapping = new Dictionary<IntPtr, Hook>();
        List<IntPtr> suspendedThreads = new List<IntPtr>();

        public Func CreateHook<Func>(string dll, string function, Func detour) where Func : Delegate {

            IntPtr target = GetProcAddress(GetModuleHandle(dll), function);

            if (target == IntPtr.Zero)
                throw new EntryPointNotFoundException($"Function {function} could not be found in DLL {dll}");

            return CreateHook<Func>(target, detour); 
        }

        public Func CreateHook<Func>(IntPtr target, Func detour) where Func : Delegate {

            if(target == IntPtr.Zero || detour == null) {
                throw new ArgumentException($"target or detour cannot be null");
            }

            lock (this) {
                var hook = new Hook(target, Marshal.GetFunctionPointerForDelegate(detour), memoryAllocator.AllocateBuffer(target));
                Func original = (Func)Marshal.GetDelegateForFunctionPointer(hook.Original, typeof(Func));
                originalHookMapping.Add(original, hook);

                //Main purpose of this is to make sure the detour delegate
                //does not get garbage collected for the lifetime of the hook
                detourHookMapping.Add(detour, hook);
                return original;
            }
        }

        // MODIFIED: 2026-08-04 支持原生 detour 地址 —— 绕过 delegate 包装, 直接用原生函数指针
        // (native stub) 作为 detour。返回值为 MinHook trampoline(Orig)的地址, 由调用方决定如何
        // 使用(填 native stub 的 Orig 表 / Marshal.GetDelegateForFunctionPointer 生成 pass-through 委托)。
        // 与 delegate 版唯一差异: 不创建/持有任何 delegate; trampoline 生成本身与 delegate 无关
        // (Trampoline 构造只接受 target/detour 两个 IntPtr)。
        public IntPtr CreateHook(IntPtr target, IntPtr nativeDetour) {

            if (target == IntPtr.Zero || nativeDetour == IntPtr.Zero) {
                throw new ArgumentException("target or nativeDetour cannot be null");
            }

            lock (this) {
                var hook = new Hook(target, nativeDetour, memoryAllocator.AllocateBuffer(target));
                nativeHookMapping.Add(target, hook);
                return hook.Original;   // trampoline 入口 = Orig
            }
        }

        public void EnableHooks() {
            foreach(var hook in originalHookMapping) {
                EnableHook(hook.Key);
            }
            // MODIFIED: 2026-08-04 原生 detour hook 一并启用
            foreach (var hook in nativeHookMapping) {
                EnableHook(hook.Key);
            }
        }

        public void DisableHooks() {
            foreach (var hook in originalHookMapping) {
                DisableHook(hook.Key);
            }
            // MODIFIED: 2026-08-04 原生 detour hook 一并禁用
            foreach (var hook in nativeHookMapping) {
                DisableHook(hook.Key);
            }
        }

        // MODIFIED: 2026-08-04 原生 detour hook 的按 target 启用/禁用重载
        public void EnableHook(IntPtr target) {
            lock (this) {
                if (!nativeHookMapping.ContainsKey(target)) {
                    throw new KeyNotFoundException("Hook not found, was this target created with CreateHook?");
                }

                SuspendThreads();
                nativeHookMapping[target].Enable(true);
                ResumeThreads();
            }
        }

        // MODIFIED: 2026-08-04 原生 detour hook 的按 target 启用/禁用重载
        public void DisableHook(IntPtr target) {
            lock (this) {
                if (!nativeHookMapping.ContainsKey(target)) {
                    throw new KeyNotFoundException("Hook not found, was this target created with CreateHook?");
                }

                SuspendThreads();
                nativeHookMapping[target].Enable(false);
                ResumeThreads();
            }
        }

        public void EnableHook(Delegate original) {
            lock (this) {
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SuspendThreads();
                originalHookMapping[original].Enable(true);
                ResumeThreads();
            }
        }

        public void DisableHook(Delegate original) {
            lock (this) {
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SuspendThreads();
                originalHookMapping[original].Enable(false);
                ResumeThreads();
            }
        }

        void SuspendThreads() {

            //Suspending all threads when debugging causes deadlocks.
            if (Debugger.IsAttached) {
                return;
            }

            //TODO: Currently doesn't move thread IP if any of the threads
            //are executing within the location of a hook prologue at the time.
            //This will probably crash the program if that scenario happens (rare)

            Process currentProc = Process.GetCurrentProcess();

            foreach(ProcessThread thread in currentProc.Threads) {
                if(thread.Id != GetCurrentThreadId()) {                    
                    IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                    SuspendThread(threadHandle);
                    suspendedThreads.Add(threadHandle);                                       
                }             
            }
        }

        void ResumeThreads() {

            foreach(var handle in suspendedThreads) {
                ResumeThread(handle);
                CloseHandle(handle);                    
            }

            suspendedThreads.Clear();
        }

        public void Dispose() {
            DisableHooks();
            memoryAllocator.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
