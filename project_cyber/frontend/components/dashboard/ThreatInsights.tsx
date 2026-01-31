import { Brain, TrendingUp } from 'lucide-react'

export default function ThreatInsights() {
  const insights = [
    {
      title: 'LockBit 3.0 Campaign',
      confidence: 87,
      description: 'Active ransomware targeting financial sector. 12 attacks in 48h.',
      indicators: ['Lateral movement', 'Data exfiltration'],
    },
    {
      title: 'APT29 Phishing Wave',
      confidence: 92,
      description: 'Sophisticated spear-phishing targeting C-level executives. 8 attempts detected.',
      indicators: ['Credential harvesting', 'Social engineering'],
    },
    {
      title: 'Emotet Botnet Resurgence',
      confidence: 78,
      description: 'Malware distribution via compromised email threads. 15 infections blocked.',
      indicators: ['Email compromise', 'Payload delivery'],
    },
    {
      title: 'SQL Injection Attempts',
      confidence: 85,
      description: 'Automated scanning targeting web applications. 47 attempts in 24h.',
      indicators: ['Database probing', 'Input validation bypass'],
    },
    {
      title: 'DDoS Attack Pattern',
      confidence: 73,
      description: 'Distributed denial of service targeting public endpoints. Traffic spike detected.',
      indicators: ['Network flooding', 'Service disruption'],
    },
  ]

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <div className="flex items-center space-x-2 mb-3">
        <Brain className="w-4 h-4 text-primary" />
        <h3 className="text-base font-semibold text-gray-900 dark:text-white">Threat Intelligence</h3>
      </div>
      <div className="space-y-2">
        {insights.map((insight, index) => (
          <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-md p-3 hover:border-primary transition-colors">
            <div className="flex items-start justify-between mb-1">
              <h4 className="text-xs font-semibold text-gray-900 dark:text-white">{insight.title}</h4>
              <div className="flex items-center space-x-1">
                <TrendingUp className="w-3 h-3 text-success" />
                <span className="text-xs font-semibold text-success">{insight.confidence}%</span>
              </div>
            </div>
            <p className="text-xs text-gray-600 dark:text-white mb-2">{insight.description}</p>
            <div className="flex flex-wrap gap-1">
              {insight.indicators.map((indicator, idx) => (
                <span
                  key={idx}
                  className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-white text-xs rounded"
                >
                  {indicator}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
