import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ToastProvider } from './components/Toast'
import { ApiKeyPrompt } from './components/ApiKeyPrompt'
import { Layout } from './components/Layout'
import { BlocklistPage } from './pages/BlocklistPage'
import { ScanSettingsPage } from './pages/ScanSettingsPage'
import { MimeTypesPage } from './pages/MimeTypesPage'

function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <ApiKeyPrompt />
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<BlocklistPage />} />
              <Route path="scan/settings" element={<ScanSettingsPage />} />
              <Route path="scan/mime-types" element={<MimeTypesPage />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  )
}

export default App
