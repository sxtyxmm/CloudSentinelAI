import { useEffect, useRef } from 'react';
import { Chart, ChartConfiguration, registerables } from 'chart.js';

Chart.register(...registerables);

interface ThreatChartProps {
  trends: any[];
}

export default function ThreatChart({ trends }: ThreatChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);

  useEffect(() => {
    if (!chartRef.current || !trends || trends.length === 0) return;

    // Destroy previous chart
    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    // Group data by date and severity
    const dates = [...new Set(trends.map((t) => t.date))].sort();
    const severities = ['critical', 'high', 'medium', 'low'];

    const datasets = severities.map((severity) => {
      const color = {
        critical: 'rgb(239, 68, 68)',
        high: 'rgb(249, 115, 22)',
        medium: 'rgb(245, 158, 11)',
        low: 'rgb(34, 197, 94)',
      }[severity];

      return {
        label: severity.charAt(0).toUpperCase() + severity.slice(1),
        data: dates.map((date) => {
          const trend = trends.find((t) => t.date === date && t.severity === severity);
          return trend ? trend.count : 0;
        }),
        borderColor: color,
        backgroundColor: color + '33',
        tension: 0.4,
      };
    });

    const config: ChartConfiguration = {
      type: 'line',
      data: {
        labels: dates,
        datasets,
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
          },
          title: {
            display: true,
            text: 'Threat Trends Over Time',
          },
        },
        scales: {
          y: {
            beginAtZero: true,
          },
        },
      },
    };

    chartInstance.current = new Chart(chartRef.current, config);

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [trends]);

  return (
    <div className="bg-white shadow rounded-lg p-6">
      <div style={{ height: '300px' }}>
        <canvas ref={chartRef}></canvas>
      </div>
    </div>
  );
}
