import React, { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { FiUploadCloud } from 'react-icons/fi'

function FileUpload({ onUpload, loading }) {
  const onDrop = useCallback(acceptedFiles => {
    if (acceptedFiles.length > 0) {
      const file = acceptedFiles[0]
      if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        onUpload(file)
      } else {
        alert('Please upload a valid .pcap or .pcapng file')
      }
    }
  }, [onUpload])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.pcap', '.pcapng']
    },
    disabled: loading
  })

  return (
    <div
      {...getRootProps()}
      className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition ${
        isDragActive
          ? 'border-blue-500 bg-blue-500/10'
          : 'border-slate-600 hover:border-blue-500 bg-slate-800/50'
      } ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
    >
      <input {...getInputProps()} />
      <FiUploadCloud className="w-16 h-16 mx-auto mb-4 text-blue-400" />
      <h2 className="text-2xl font-bold text-white mb-2">
        {loading ? 'Analyzing...' : 'Drop your Wireshark file here'}
      </h2>
      <p className="text-slate-400 text-lg mb-4">
        or click to select a .pcap or .pcapng file
      </p>
      <div className="bg-slate-700/50 rounded px-4 py-2 inline-block text-sm text-slate-300">
        Supported: .pcap, .pcapng
      </div>
    </div>
  )
}

export default FileUpload
