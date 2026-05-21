import { motion } from 'framer-motion'

export default function ProgressBar({ progress = 0, label = '' }) {
  return (
    <div className="w-full max-w-md mx-auto">
      {label && <p className="text-sm text-gray-600 mb-2 text-center">{label}</p>}
      <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
        <motion.div
          className="h-full bg-gradient-to-r from-blue-500 to-blue-700 rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
        />
      </div>
      <p className="text-xs text-gray-500 mt-1 text-center">{progress}%</p>
    </div>
  )
}
