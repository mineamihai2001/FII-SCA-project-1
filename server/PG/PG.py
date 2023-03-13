class PaymentGateway:
    PubKPG: any
    PrivKPG: any
    def __init__(self, PubKPG, PrivKPG) -> None:
        self.PubKPG = PubKPG
        self.PrivKPG = PrivKPG

    def step4(self, message):
        print(message)