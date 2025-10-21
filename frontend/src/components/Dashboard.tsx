import { useEffect, useState } from 'react';
import { dashboardAPI, alertsAPI } from '@/services/api';
import StatsCards from './StatsCards';
import AlertsList from './AlertsList';
import ThreatChart from './ThreatChart';
import ActivityHeatmap from './ActivityHeatmap';

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [trends, setTrends] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [statsRes, alertsRes, trendsRes] = await Promise.all([
        dashboardAPI.getStats(),
        alertsAPI.getAlerts({ limit: 10 }),
        dashboardAPI.getTrends(7),
      ]);

      setStats(statsRes.data);
      setAlerts(alertsRes.data);
      setTrends(trendsRes.data);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    window.location.href = '/login';
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-gray-900">CloudSentinelAI</h1>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => loadDashboardData()}
              className="px-4 py-2 text-sm font-medium text-white bg-primary rounded-md hover:bg-indigo-700"
            >
              Refresh
            </button>
            <button
              onClick={handleLogout}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-200 rounded-md hover:bg-gray-300"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {['overview', 'alerts', 'analytics'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? 'border-primary text-primary'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <StatsCards stats={stats} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ThreatChart trends={trends} />
              <AlertsList alerts={alerts.slice(0, 5)} />
            </div>
          </div>
        )}

        {activeTab === 'alerts' && (
          <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">All Alerts</h2>
            <AlertsList alerts={alerts} showAll={true} />
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <ActivityHeatmap />
            <ThreatChart trends={trends} />
          </div>
        )}
      </main>
    </div>
  );
}
