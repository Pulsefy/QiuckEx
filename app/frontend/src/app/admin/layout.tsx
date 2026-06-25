import { redirect } from "next/navigation";
import { ReactNode } from "react";

// Mock auth check
const checkIsAdmin = () => {
  // In a real app, this would check cookies/session
  const isAdmin = true; // Set to true for demo purposes
  return isAdmin;
};

export default function AdminLayout({ children }: { children: ReactNode }) {
  if (!checkIsAdmin()) {
    redirect("/"); // Admin routes are inaccessible to non-admin users
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="bg-card border-b border-border px-6 py-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-foreground">Admin Console</h1>
        <div className="text-sm bg-brand-soft text-brand px-3 py-1 rounded-full font-medium">Admin Active</div>
      </header>
      <main className="flex-1 p-6">
        {children}
      </main>
    </div>
  );
}
