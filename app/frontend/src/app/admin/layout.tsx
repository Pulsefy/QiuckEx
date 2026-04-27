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
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <header className="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-800">Admin Console</h1>
        <div className="text-sm bg-blue-100 text-blue-800 px-3 py-1 rounded-full font-medium">Admin Active</div>
      </header>
      <main className="flex-1 p-6">
        {children}
      </main>
    </div>
  );
}
