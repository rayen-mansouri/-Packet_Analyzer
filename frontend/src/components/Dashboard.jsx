import React from 'react'
import { FiBar3, FiShield, FiActivity, FiNetwork } from 'react-icons/fi'

function Dashboard() {
  const features = [
    {
      icon: FiBar3,
      title: 'Packet Decomposition',
      description: 'Parse and analyze packet structure with detailed metadata'
    },
    {
      icon: FiShield,
      title: 'Threat Detection',
      description: 'Identify port scans, SYN floods, brute force, and malware C2'
    },
    {
      icon: FiActivity,
      title: 'Timeline Analysis',
      description: 'Visualize traffic patterns and communication timeline'
    },
    {
      icon: FiNetwork,
      title: 'IP Mapping',
      description: 'Interactive graphs of IP relationships and protocols'
    }
  ]

  return (
    <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-8">
      <h2 className="text-2xl font-bold text-white mb-8">Features</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {features.map((feature, idx) => {
          const Icon = feature.icon
          return (
            <div key={idx} className="bg-slate-700/30 border border-slate-600 rounded-lg p-6 hover:border-blue-500 transition">
              <Icon className="w-8 h-8 text-blue-400 mb-4" />
              <h3 className="font-semibold text-white mb-2">{feature.title}</h3>
              <p className="text-slate-400 text-sm">{feature.description}</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default Dashboard
