import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../api/axios'
import LoadingSpinner from '../components/LoadingSpinner'
import ProgressBar from '../components/ProgressBar'

const STEPS = {
  LOADING: 'loading',
  READY: 'ready',
  DOWNLOADING: 'downloading',
  COLLECTING: 'collecting',
  SUCCESS: 'success',
  ALREADY_DONE: 'already_done',
  ERROR: 'error',
  INVALID: 'invalid',
}

export default function VerificationPage() {
  const { token } = useParams()
  const [step, setStep] = useState(STEPS.LOADING)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState('')

  useEffect(() => {
    verifyToken()
  }, [token])

  const verifyToken = async () => {
    try {
      const { data } = await api.get(`/audit/verify/${token}`)
      if (data.status === 'completed') {
        setStep(STEPS.ALREADY_DONE)
      } else {
        setStep(STEPS.READY)
      }
    } catch {
      setStep(STEPS.INVALID)
    }
  }

  const startVerification = () => {
    setStep(STEPS.DOWNLOADING)
    setProgress(10)

    // Trigger agent download
    const link = document.createElement('a')
    link.href = '/api/audit/download-agent'
    link.download = 'SystemAuditAgent.exe'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)

    setTimeout(() => setProgress(20), 1500)
    setTimeout(() => setProgress(30), 3000)
    setTimeout(() => {
      setStep(STEPS.COLLECTING)
      setProgress(40)
    }, 4000)

    // Simulate gradual progress while waiting for agent
    let simulatedProgress = 40
    const progressInterval = setInterval(() => {
      simulatedProgress = Math.min(simulatedProgress + 2, 90)
      setProgress(simulatedProgress)
    }, 5000)

    // Poll for completion
    let completed = false
    const pollInterval = setInterval(async () => {
      try {
        const { data } = await api.get(`/audit/verify/${token}`)
        if (data.status === 'completed') {
          completed = true
          clearInterval(pollInterval)
          clearInterval(progressInterval)
          setProgress(100)
          setTimeout(() => setStep(STEPS.SUCCESS), 500)
        }
      } catch {
        // keep polling
      }
    }, 3000)

    // Timeout after 5 minutes
    setTimeout(() => {
      if (!completed) {
        clearInterval(pollInterval)
        clearInterval(progressInterval)
        setError('Timed out waiting for agent. Please ensure the agent is running.')
        setStep(STEPS.ERROR)
      }
    }, 300000)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0f1b2d] via-[#1a365d] to-[#0f1b2d] flex flex-col">
      {/* NSDL Header Bar */}
      <div className="bg-[#1a365d] border-b border-[#2d4a7a] px-6 py-3">
        <div className="max-w-lg mx-auto flex items-center justify-between">
          <span className="text-white font-bold text-sm tracking-wide">NSDL e-Governance</span>
          <span className="text-blue-300 text-xs">System Inspection Portal</span>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden"
        >
          {/* Card Header */}
          <div className="bg-[#1a365d] px-8 py-5">
            <h1 className="text-xl font-bold text-white">System Inspection</h1>
            <p className="text-blue-300 text-sm mt-1">NSDL e-Governance Infrastructure Ltd.</p>
          </div>

          <div className="p-8">
            <AnimatePresence mode="wait">
              {/* LOADING */}
              {step === STEPS.LOADING && (
                <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <LoadingSpinner text="Validating inspection link..." />
                </motion.div>
              )}

              {/* INVALID TOKEN */}
              {step === STEPS.INVALID && (
                <motion.div key="invalid" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-center">
                  <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </div>
                  <h2 className="text-xl font-semibold text-gray-800 mb-2">Invalid Link</h2>
                  <p className="text-gray-500 text-sm">This inspection link is invalid or has expired.</p>
                </motion.div>
              )}

              {/* ALREADY DONE */}
              {step === STEPS.ALREADY_DONE && (
                <motion.div key="done" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-center">
                  <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <h2 className="text-xl font-semibold text-gray-800 mb-2">Already Inspected</h2>
                  <p className="text-gray-500 text-sm">This system inspection has already been completed.</p>
                </motion.div>
              )}

              {/* READY */}
              {step === STEPS.READY && (
                <motion.div key="ready" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  {/* Consent */}
                  <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 mb-6">
                    <h3 className="font-semibold text-[#1a365d] text-sm mb-2">Consent & Process</h3>
                    <p className="text-sm text-blue-800 mb-3">
                      We provide approval to NSDL e-Governance Infrastructure Ltd. (NSDL e-Gov)
                      to capture the details regarding the System details and share the details
                      with NSDL e-Gov.
                    </p>
                    <ul className="text-sm text-blue-700 space-y-1">
                      <li>1. A lightweight inspection agent will be downloaded</li>
                      <li>2. Run the agent on your Windows PC</li>
                      <li>3. System details are collected (OS, drives, printers, etc.)</li>
                      <li>4. Data is uploaded securely for inspection report</li>
                    </ul>
                  </div>
                  <button
                    onClick={startVerification}
                    className="w-full bg-[#1a365d] hover:bg-[#2d4a7a] text-white font-semibold py-3.5 px-6 rounded-xl transition-all shadow-lg hover:shadow-xl active:scale-[0.98]"
                  >
                    Start Inspection
                  </button>
                  <p className="text-xs text-gray-400 text-center mt-4">
                    By clicking, you consent to a system inspection of your PC.
                  </p>
                </motion.div>
              )}

              {/* DOWNLOADING / COLLECTING */}
              {(step === STEPS.DOWNLOADING || step === STEPS.COLLECTING) && (
                <motion.div key="progress" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <LoadingSpinner
                    text={step === STEPS.DOWNLOADING ? 'Downloading inspection agent...' : 'Collecting system information...'}
                  />
                  <div className="mt-6">
                    <ProgressBar
                      progress={progress}
                      label={step === STEPS.DOWNLOADING ? 'Preparing agent...' : 'Scanning system details...'}
                    />
                  </div>
                  <p className="text-xs text-gray-400 text-center mt-4">
                    Please run the downloaded agent and wait for it to complete.
                    <br />The agent will collect OS, drive, printer, and network details.
                  </p>
                </motion.div>
              )}

              {/* SUCCESS */}
              {step === STEPS.SUCCESS && (
                <motion.div key="success" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }} className="text-center">
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: 'spring', stiffness: 200, delay: 0.2 }}
                    className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4"
                  >
                    <svg className="w-10 h-10 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </motion.div>
                  <h2 className="text-xl font-bold text-gray-800 mb-2">Inspection Successful</h2>
                  <p className="text-gray-500 text-sm">
                    Your system inspection has been completed successfully.
                    <br />The inspection report has been generated. You may close this window.
                  </p>
                </motion.div>
              )}

              {/* ERROR */}
              {step === STEPS.ERROR && (
                <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-center">
                  <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <h2 className="text-xl font-semibold text-gray-800 mb-2">Error</h2>
                  <p className="text-gray-500 text-sm">{error || 'Something went wrong. Please try again.'}</p>
                  <button
                    onClick={() => { setStep(STEPS.READY); setProgress(0) }}
                    className="mt-4 text-[#1a365d] hover:text-[#2d4a7a] text-sm font-medium"
                  >
                    Try Again
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Card Footer */}
          <div className="bg-gray-50 px-8 py-3 border-t border-gray-100">
            <p className="text-xs text-[#800000] text-center">INSPECTION REPORT BY NSDL E-GOVERNANCE</p>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
