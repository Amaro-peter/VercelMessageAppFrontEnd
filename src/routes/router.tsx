import { createBrowserRouter } from "react-router-dom";
import LoginPage from "../pages/LoginPage";
import MessagePage from "../pages/MessagePage";

const router = createBrowserRouter([
    {
        path: "/",
        children: [
            {
                path: "",
                element: <LoginPage />, 
            },
            {
                path: "messages",
                element: <MessagePage />,
            }
        ] 
    },
]);

export default router;