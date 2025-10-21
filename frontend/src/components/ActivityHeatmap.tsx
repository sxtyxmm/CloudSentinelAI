import { useEffect, useState } from 'react';
import { dashboardAPI } from '@/services/api';

export default function ActivityHeatmap() {
  const [heatmapData, setHeatmapData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadHeatmapData();
  }, []);

  const loadHeatmapData = async () => {
    try {
      const response = await dashboardAPI.getActivityHeatmap(7);
      setHeatmapData(response.data);
    } catch (error) {
      console.error('Error loading heatmap:', error);
    } finally {
      setLoading(false);
    }
  };

  const getColorIntensity = (value: number, max: number) => {
    if (value === 0) return 'bg-gray-100';
    const intensity = Math.ceil((value / max) * 4);
    const colors = [
      'bg-blue-100',
      'bg-blue-300',
      'bg-blue-500',
      'bg-blue-700',
      'bg-blue-900',
    ];
    return colors[intensity] || colors[0];
  };

  if (loading) {
    return (
      <div className="bg-white shadow rounded-lg p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  if (!heatmapData) return null;

  const maxValue = Math.max(
    ...heatmapData.heatmap.flat().filter((v: number) => v > 0)
  );

  return (
    <div className="bg-white shadow rounded-lg p-6">
      <h3 className="text-lg font-medium text-gray-900 mb-4">
        Activity Heatmap (Last 7 Days)
      </h3>
      <div className="overflow-x-auto">
        <div className="inline-block min-w-full">
          <div className="grid grid-cols-25 gap-1">
            {/* Header row with hours */}
            <div className="col-span-1"></div>
            {heatmapData.hours.map((hour: number) => (
              <div
                key={hour}
                className="text-xs text-center text-gray-600 font-medium"
              >
                {hour}
              </div>
            ))}
            
            {/* Heatmap rows */}
            {heatmapData.days.map((day: string, dayIndex: number) => (
              <>
                <div
                  key={`day-${dayIndex}`}
                  className="text-xs text-right text-gray-600 font-medium pr-2"
                >
                  {day}
                </div>
                {heatmapData.heatmap[dayIndex].map((value: number, hourIndex: number) => (
                  <div
                    key={`${dayIndex}-${hourIndex}`}
                    className={`h-8 rounded ${getColorIntensity(value, maxValue)} ${
                      value > 0 ? 'cursor-pointer' : ''
                    }`}
                    title={`${day} ${hourIndex}:00 - ${value} alerts`}
                  ></div>
                ))}
              </>
            ))}
          </div>
        </div>
      </div>
      <div className="mt-4 flex items-center justify-end space-x-2 text-xs text-gray-600">
        <span>Less</span>
        <div className="flex space-x-1">
          <div className="w-4 h-4 bg-gray-100 rounded"></div>
          <div className="w-4 h-4 bg-blue-100 rounded"></div>
          <div className="w-4 h-4 bg-blue-300 rounded"></div>
          <div className="w-4 h-4 bg-blue-500 rounded"></div>
          <div className="w-4 h-4 bg-blue-700 rounded"></div>
          <div className="w-4 h-4 bg-blue-900 rounded"></div>
        </div>
        <span>More</span>
      </div>
    </div>
  );
}
