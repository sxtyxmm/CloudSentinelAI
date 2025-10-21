interface StatsCardsProps {
  stats: any;
}

export default function StatsCards({ stats }: StatsCardsProps) {
  if (!stats) return null;

  const cards = [
    {
      title: 'Total Alerts',
      value: stats.total_alerts || 0,
      color: 'bg-blue-500',
      icon: '🚨',
    },
    {
      title: 'Critical Alerts',
      value: stats.critical_alerts || 0,
      color: 'bg-red-500',
      icon: '⚠️',
    },
    {
      title: 'High Severity',
      value: stats.high_alerts || 0,
      color: 'bg-orange-500',
      icon: '🔥',
    },
    {
      title: 'Open Alerts',
      value: stats.open_alerts || 0,
      color: 'bg-yellow-500',
      icon: '📋',
    },
    {
      title: 'Resolved',
      value: stats.resolved_alerts || 0,
      color: 'bg-green-500',
      icon: '✅',
    },
    {
      title: 'False Positives',
      value: stats.false_positives || 0,
      color: 'bg-gray-500',
      icon: '❌',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {cards.map((card, index) => (
        <div
          key={index}
          className="bg-white overflow-hidden shadow rounded-lg"
        >
          <div className="p-5">
            <div className="flex items-center">
              <div className={`flex-shrink-0 ${card.color} rounded-md p-3 text-2xl`}>
                {card.icon}
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    {card.title}
                  </dt>
                  <dd className="text-2xl font-semibold text-gray-900">
                    {card.value}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
