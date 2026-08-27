import { Compass } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button, Card, EmptyState } from '../components/ui'

function NotFoundPage() {
  const navigate = useNavigate()

  return (
    <div className="p-5">
      <Card>
        <EmptyState
          icon={<Compass className="h-5 w-5" />}
          message="That page does not exist"
          hint="The address may be out of date, or the feature may not be part of NightOwl."
          action={
            <Button className="mt-2" variant="primary" onClick={() => navigate('/')}>
              Back to overview
            </Button>
          }
        />
      </Card>
    </div>
  )
}

export default NotFoundPage
