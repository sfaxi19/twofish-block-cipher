package exceptions;

/**
 * Created by sfaxi19 on 02.11.16.
 */
public class WhiteningException extends RuntimeException {
    private String message = "";

    public WhiteningException(final String msg) {
        super(msg);
        this.message = msg;
    }

    public String getMessage() {
        return message;
    }
}
