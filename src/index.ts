import express, {type Express} from 'express'
import { config } from './utils/config'

const app: Express = express()

const PORT = config.PORT || 3001
app.listen(PORT, ()=>{
    console.log(`Bugkhoj server is running at ${PORT}`)
})