import { Play, Pause, RotateCcw, Target, Zap } from 'lucide-react'

export default function AttackSimulator() {
  const mitrePhases = [
    { id: 1, name: 'Initial Access', techniques: 12, active: true },
    { id: 2, name: 'Execution', techniques: 8, active: true },
    { id: 3, name: 'Persistence', techniques: 15, active: false },
    { id: 4, name: 'Privilege Escalation', techniques: 11, active: false },
    { id: 5, name: 'Defense Evasion', techniques: 18, active: false },
    { id: 6, name: 'Credential Access', techniques: 9, active: false },
    { id: 7, name: 'Discovery', techniques: 14, active: false },
    { id: 8, name: 'Lateral Movement', techniques: 7, active: false },
    { id: 9, name: 'Collection', techniques: 10, active: false },
    { id: 10, name: 'Exfiltration', techniques: 6, active: false },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Attack Path Simulator</h1>
        <div className="flex items-center space-x-3">
          <button className="flex items-center space-x-2 px-4 py-2 bg-success text-white rounded-md hover:bg-green-700 transition-colors">
            <Play className="w-4 h-4" />
            <span className="text-sm font-medium">Start Simulation</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-white rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
            <Pause className="w-4 h-4" />
            <span className="text-sm font-medium">Pause</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-white rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
            <RotateCcw className="w-4 h-4" />
            <span className="text-sm font-medium">Reset</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Graph Canvas */}
        <div className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Attack Path Visualization</h3>
          <div className="bg-gray-50 dark:bg-gray-700 rounded-md h-96 flex items-center justify-center border-2 border-dashed border-gray-300 dark:border-gray-600">
            <div className="text-center">
              <Target className="w-16 h-16 text-gray-400 dark:text-gray-500 mx-auto mb-3" />
              <p className="text-gray-600 dark:text-white font-medium">Interactive Attack Graph</p>
              <p className="text-sm text-gray-500 dark:text-gray-300 mt-1">Visualizes attack paths and impact</p>
            </div>
          </div>
        </div>

        {/* Impact Estimation */}
        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Impact Estimation</h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-700 dark:text-white font-medium">Business Impact</span>
                <span className="text-critical font-semibold">HIGH</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div className="bg-critical h-2 rounded-full" style={{ width: '85%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-700 dark:text-white font-medium">Financial Loss</span>
                <span className="text-gray-900 dark:text-white font-semibold">$2.4M</span>
              </div>
              <div className="text-xs text-gray-600 dark:text-white">Estimated revenue impact</div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-700 dark:text-white font-medium">Assets at Risk</span>
                <span className="text-gray-900 dark:text-white font-semibold">47</span>
              </div>
              <div className="text-xs text-gray-600 dark:text-white">Critical systems affected</div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-700 dark:text-white font-medium">Recovery Time</span>
                <span className="text-gray-900 dark:text-white font-semibold">72 hours</span>
              </div>
              <div className="text-xs text-gray-600 dark:text-white">Estimated downtime</div>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Mapping */}
      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
        <div className="flex items-center space-x-2 mb-4">
          <Zap className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">MITRE ATT&CK Tactics</h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {mitrePhases.map((phase) => (
            <div
              key={phase.id}
              className={`p-4 rounded-md border-2 transition-all cursor-pointer ${
                phase.active
                  ? 'border-primary bg-blue-50 dark:bg-blue-900/30'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <div className="text-sm font-semibold text-gray-900 dark:text-white mb-1">{phase.name}</div>
              <div className="text-xs text-gray-600 dark:text-white">{phase.techniques} techniques</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
