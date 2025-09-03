import { createRoot } from 'react-dom/client'
import './index.css'
import "bootstrap/dist/css/bootstrap.min.css"
import "bootstrap/dist/js/bootstrap.bundle.min.js"
import { RouterProvider } from 'react-router-dom'
import router from './routes/router'

createRoot(document.getElementById('root')!).render(
  <RouterProvider router={router} />
)
