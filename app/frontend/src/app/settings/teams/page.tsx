"use client";

import { useState } from "react";
import Link from "next/link";

interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: "admin" | "operator" | "viewer";
  status: "active" | "pending";
}

const initialMembers: TeamMember[] = [
  { id: "1", name: "John Doe", email: "john@quickex.to", role: "admin", status: "active" },
  { id: "2", name: "Sarah Smith", email: "sarah@quickex.to", role: "operator", status: "active" },
  { id: "3", name: "Mike Wilson", email: "mike@external.com", role: "viewer", status: "pending" },
];

export default function TeamSettings() {
  const [members, setMembers] = useState<TeamMember[]>(initialMembers);
  const [userRole] = useState<"admin" | "operator" | "viewer">("admin"); // Mock current user role

  const handleRoleChange = (memberId: string, newRole: "admin" | "operator" | "viewer") => {
    if (userRole !== "admin") return;
    setMembers(members.map(m => m.id === memberId ? { ...m, role: newRole } : m));
  };

  const removeMember = (memberId: string) => {
    if (userRole !== "admin") return;
    setMembers(members.filter(m => m.id !== memberId));
  };

  return (
    <div className="relative min-h-screen text-white">
      {/* Background glows */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] rounded-full" />

      {/* DESKTOP SIDEBAR (Reused from settings) */}
      <aside className="hidden md:flex w-72 h-screen fixed left-0 top-0 border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col z-20">
        <nav className="flex-1 px-4 py-30 space-y-2">
          <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold transition">
            <span>📊</span> Dashboard
          </Link>
          <Link href="/settings" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold transition">
            <span>⚙️</span> Profile Settings
          </Link>
          <Link href="/settings/teams" className="flex items-center gap-3 px-4 py-3 bg-white/5 border border-white/5 rounded-2xl font-bold">
            <span className="text-indigo-400">👥</span> Team Management
          </Link>
        </nav>
      </aside>

      <main className="relative z-10 p-4 sm:p-6 md:p-12 md:ml-72">
        <header className="mb-10">
          <h1 className="text-3xl font-black tracking-tight mb-2">Team Management</h1>
          <p className="text-neutral-500 font-medium">Manage members, roles, and workspace permissions.</p>
        </header>

        <nav className="flex gap-3 mb-8">
          <Link href="/settings" className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold hover:bg-white/5 transition">
            General
          </Link>
          <Link href="/settings/teams" className="px-4 py-2 rounded-xl border border-white/10 bg-white/10 text-sm font-semibold">
            Team
          </Link>
          <Link href="/settings/developer" className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold hover:bg-white/5 transition">
            Developer
          </Link>
        </nav>

        <div className="rounded-3xl bg-black/40 border border-white/5 overflow-hidden">
          <div className="p-6 border-b border-white/5 flex justify-between items-center">
            <h2 className="text-xl font-bold">Workspace Members</h2>
            <button 
              disabled={userRole !== "admin"}
              className={`px-4 py-2 bg-indigo-500 text-white text-sm font-bold rounded-xl transition ${userRole !== "admin" ? "opacity-50 cursor-not-allowed" : "hover:scale-105"}`}
            >
              + Invite Member
              {userRole !== "admin" && (
                <span className="block text-[10px] text-indigo-200 font-medium">Admin only</span>
              )}
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-neutral-500 text-xs font-bold uppercase tracking-wider">
                  <th className="px-6 py-4">Member</th>
                  <th className="px-6 py-4">Role</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {members.map((member) => (
                  <tr key={member.id} className="group hover:bg-white/[0.02] transition">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-neutral-800 rounded-full flex items-center justify-center font-bold text-indigo-400">
                          {member.name[0]}
                        </div>
                        <div>
                          <p className="font-bold">{member.name}</p>
                          <p className="text-xs text-neutral-500">{member.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <select 
                        value={member.role}
                        disabled={userRole !== "admin" || member.id === "1"} // Can't change own role or if not admin
                        onChange={(e) => handleRoleChange(member.id, e.target.value as any)}
                        className="bg-neutral-900 border border-white/10 rounded-lg px-2 py-1 text-sm outline-none focus:border-indigo-500 transition disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <option value="admin">Admin</option>
                        <option value="operator">Operator</option>
                        <option value="viewer">Viewer</option>
                      </select>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded-md text-[10px] font-black uppercase tracking-widest ${
                        member.status === "active" ? "bg-emerald-500/10 text-emerald-500" : "bg-amber-500/10 text-amber-500"
                      }`}>
                        {member.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={() => removeMember(member.id)}
                        disabled={userRole !== "admin" || member.id === "1"}
                        className="p-2 text-neutral-500 hover:text-red-500 transition disabled:opacity-0"
                      >
                        🗑️
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Role Descriptions */}
        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-white/5 border border-white/5">
            <p className="text-indigo-400 font-black text-xs uppercase mb-2">Admin</p>
            <p className="text-sm text-neutral-400">Full access to all settings, team management, and financial operations.</p>
          </div>
          <div className="p-6 rounded-2xl bg-white/5 border border-white/5">
            <p className="text-purple-400 font-black text-xs uppercase mb-2">Operator</p>
            <p className="text-sm text-neutral-400">Can manage links and view analytics, but cannot manage team or workspace settings.</p>
          </div>
          <div className="p-6 rounded-2xl bg-white/5 border border-white/5">
            <p className="text-neutral-400 font-black text-xs uppercase mb-2">Viewer</p>
            <p className="text-sm text-neutral-400">Read-only access to dashboard and analytics. Cannot perform any actions.</p>
          </div>
        </div>
      </main>
    </div>
  );
}
