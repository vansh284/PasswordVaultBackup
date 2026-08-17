import React from 'react';

export default function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-6 flex flex-col items-center justify-center">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-xl space-y-6">
        <div className="border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
            <span className="text-xs font-mono font-semibold text-emerald-400 uppercase tracking-wider">
              C# .NET 10 / ASP.NET Core POC
            </span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Secure Password Vault Backup API
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Zero-Knowledge Architecture & Public Key Authentication
          </p>
        </div>

        <div className="space-y-4 text-xs sm:text-sm text-slate-300">
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <h2 className="font-semibold text-white font-mono text-xs uppercase tracking-wider">
              C# Solution Structure:
            </h2>
            <ul className="space-y-1 font-mono text-xs text-slate-400">
              <li><strong className="text-blue-400">VaultShared/</strong> &mdash; Cryptographic primitives (PBKDF2, HKDF, ECDSA NIST P-256, AES-256-GCM)</li>
              <li><strong className="text-amber-400">VaultServer/</strong> &mdash; ASP.NET Core Minimal API with SQLite storage & AuthMiddleware</li>
              <li><strong className="text-emerald-400">VaultClient/</strong> &mdash; Console client running full 7-step zero-knowledge lifecycle</li>
            </ul>
          </div>

          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2 font-mono text-xs">
            <div className="text-slate-400"># Run the Server:</div>
            <div className="text-emerald-400 bg-slate-900 p-2.5 rounded border border-slate-800 select-all">
              dotnet run --project VaultServer
            </div>
            <div className="text-slate-400 mt-2"># Run the Client:</div>
            <div className="text-emerald-400 bg-slate-900 p-2.5 rounded border border-slate-800 select-all">
              dotnet run --project VaultClient
            </div>
          </div>
        </div>

        <div className="text-xs text-slate-500 border-t border-slate-800 pt-4 flex items-center justify-between">
          <span>Pure .NET 10 BCL (System.Security.Cryptography)</span>
          <span>Zero-Knowledge Proof of Concept</span>
        </div>
      </div>
    </div>
  );
}
