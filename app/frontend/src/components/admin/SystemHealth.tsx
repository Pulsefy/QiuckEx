import { Activity, Clock, ServerCrash } from "lucide-react";

export function SystemHealth() {
  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <h2 className="text-lg font-semibold text-gray-800 mb-4">System Health</h2>
      
      <div className="grid grid-cols-2 gap-4">
        <div className="p-4 bg-green-50 rounded-lg border border-green-100">
          <div className="flex items-center space-x-2 text-green-600 mb-2">
            <Activity className="h-5 w-5" />
            <span className="font-medium">API Status</span>
          </div>
          <p className="text-2xl font-bold text-gray-800">Operational</p>
        </div>

        <div className="p-4 bg-yellow-50 rounded-lg border border-yellow-100">
          <div className="flex items-center space-x-2 text-yellow-600 mb-2">
            <Clock className="h-5 w-5" />
            <span className="font-medium">Ingestion Lag</span>
          </div>
          <p className="text-2xl font-bold text-gray-800">1.2s</p>
        </div>

        <div className="p-4 bg-blue-50 rounded-lg border border-blue-100 col-span-2">
          <div className="flex items-center space-x-2 text-blue-600 mb-2">
            <ServerCrash className="h-5 w-5" />
            <span className="font-medium">Webhook Backlog</span>
          </div>
          <div className="flex items-end justify-between">
            <p className="text-2xl font-bold text-gray-800">42</p>
            <span className="text-sm text-blue-600 font-medium">Processing...</span>
          </div>
          <div className="w-full bg-blue-200 rounded-full h-2 mt-3">
            <div className="bg-blue-600 h-2 rounded-full" style={{ width: '45%' }}></div>
          </div>
        </div>
      </div>
    </div>
  );
}
