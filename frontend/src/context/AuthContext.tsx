import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

interface AuthContextValue {
  apiKey: string
  actorName: string
  showPrompt: boolean
  setApiKey: (key: string) => void
  setActorName: (name: string) => void
  setShowPrompt: (v: boolean) => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [apiKey, setApiKeyState] = useState(() => localStorage.getItem('apiKey') ?? '')
  const [actorName, setActorNameState] = useState(() => localStorage.getItem('actorName') ?? '')
  const [showPrompt, setShowPrompt] = useState(() => !localStorage.getItem('apiKey'))

  const setApiKey = (key: string) => {
    localStorage.setItem('apiKey', key)
    setApiKeyState(key)
  }
  const setActorName = (name: string) => {
    localStorage.setItem('actorName', name)
    setActorNameState(name)
  }

  useEffect(() => {
    const handler = () => setShowPrompt(true)
    window.addEventListener('auth:unauthorized', handler)
    return () => window.removeEventListener('auth:unauthorized', handler)
  }, [])

  return (
    <AuthContext.Provider value={{ apiKey, actorName, showPrompt, setApiKey, setActorName, setShowPrompt }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
